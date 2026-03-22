#!/usr/bin/env python3
"""
coap_scan.py — CoAP Resource Discovery & Fuzzer
Uso: python3 coap_scan.py <target> [--port 5683] [--action discover|get|put|observe]
Implementa CoAP packet builder/parser manuale (no librerie esterne)
"""

import argparse
import socket
import struct
import random
import sys
import re
import time

# CoAP constants
COAP_VERSION = 1
# Message types
TYPE_CON = 0   # Confirmable
TYPE_NON = 1   # Non-confirmable
TYPE_ACK = 2
TYPE_RST = 3

# Codes: request
CODE_GET  = 0x01
CODE_POST = 0x02
CODE_PUT  = 0x03
CODE_DEL  = 0x04

# Option numbers
OPT_IF_MATCH       = 1
OPT_URI_HOST       = 3
OPT_ETAG           = 4
OPT_URI_PATH       = 11
OPT_CONTENT_FORMAT = 12
OPT_MAX_AGE        = 14
OPT_URI_QUERY      = 15
OPT_ACCEPT         = 17
OPT_OBSERVE        = 6

# Response code helpers
def code_to_str(code):
    cls = (code >> 5) & 0x07
    det = code & 0x1F
    known = {
        (2, 5): "2.05 Content",
        (2, 1): "2.01 Created",
        (2, 2): "2.02 Deleted",
        (2, 3): "2.03 Valid",
        (2, 4): "2.04 Changed",
        (4, 0): "4.00 Bad Request",
        (4, 1): "4.01 Unauthorized",
        (4, 3): "4.03 Forbidden",
        (4, 4): "4.04 Not Found",
        (4, 5): "4.05 Method Not Allowed",
        (5, 0): "5.00 Internal Server Error",
    }
    return known.get((cls, det), f"{cls}.{det:02d}")

def encode_option(opt_num, opt_val, prev_opt_num=0):
    """Encode a CoAP option with delta encoding"""
    if isinstance(opt_val, str):
        opt_val = opt_val.encode('utf-8')
    elif isinstance(opt_val, int):
        # encode as minimal bytes
        if opt_val == 0:
            opt_val = b'\x00'
        else:
            length = (opt_val.bit_length() + 7) // 8
            opt_val = opt_val.to_bytes(length, 'big')

    delta = opt_num - prev_opt_num
    length = len(opt_val)

    def _encode_nibble(val):
        if val < 13:
            return val, b''
        elif val < 269:
            return 13, struct.pack('>B', val - 13)
        else:
            return 14, struct.pack('>H', val - 269)

    d_nibble, d_ext = _encode_nibble(delta)
    l_nibble, l_ext = _encode_nibble(length)

    header = bytes([(d_nibble << 4) | l_nibble])
    return header + d_ext + l_ext + opt_val

def build_coap_packet(msg_type, code, msg_id, token, options, payload=b''):
    """Build a raw CoAP packet"""
    tkl = len(token)
    # Header: Ver(2)+T(2)+TKL(4) + Code(8) + Message ID(16)
    first_byte = (COAP_VERSION << 6) | (msg_type << 4) | tkl
    header = struct.pack('>BBH', first_byte, code, msg_id)

    # Options (must be in ascending order by option number)
    opts_bytes = b''
    prev = 0
    for opt_num, opt_val in sorted(options, key=lambda x: x[0]):
        opts_bytes += encode_option(opt_num, opt_val, prev)
        prev = opt_num

    # Payload marker
    if payload:
        return header + token + opts_bytes + b'\xff' + payload
    else:
        return header + token + opts_bytes

def parse_coap_response(data):
    """Parse a CoAP response, return (code_str, payload_bytes, options_dict)"""
    if len(data) < 4:
        return None, None, {}
    first_byte = data[0]
    ver   = (first_byte >> 6) & 0x03
    mtype = (first_byte >> 4) & 0x03
    tkl   = first_byte & 0x0F
    code  = data[1]
    msg_id = struct.unpack('>H', data[2:4])[0]
    token = data[4:4+tkl]
    idx = 4 + tkl

    options = {}
    opt_num = 0
    while idx < len(data):
        b = data[idx]
        if b == 0xFF:
            idx += 1
            break
        d_nibble = (b >> 4) & 0x0F
        l_nibble = b & 0x0F
        idx += 1

        def decode_nibble(nibble, data, idx):
            if nibble < 13:
                return nibble, idx
            elif nibble == 13:
                return data[idx] + 13, idx + 1
            elif nibble == 14:
                return struct.unpack('>H', data[idx:idx+2])[0] + 269, idx + 2
            else:
                return 0, idx  # 15 reserved

        delta, idx = decode_nibble(d_nibble, data, idx)
        length, idx = decode_nibble(l_nibble, data, idx)
        opt_num += delta
        opt_val = data[idx:idx+length]
        idx += length
        options[opt_num] = opt_val

    payload = data[idx:]
    return code_to_str(code), payload, options

def send_coap_udp(target, port, packet, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (target, port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    except Exception as e:
        return None
    finally:
        sock.close()

def send_and_parse(target, port, packet, timeout=5):
    resp = send_coap_udp(target, port, packet, timeout)
    if not resp:
        return None, None, {}
    return parse_coap_response(resp)

def random_token(n=4):
    return bytes(random.randint(0, 255) for _ in range(n))

def random_msg_id():
    return random.randint(1, 65535)

def action_discover(target, port):
    """GET /.well-known/core"""
    print(f"[*] CoAP Resource Discovery — {target}:{port}")
    token = random_token()
    options = [
        (OPT_URI_HOST, target),
        (OPT_URI_PATH, ".well-known"),
        (OPT_URI_PATH, "core"),
    ]
    pkt = build_coap_packet(TYPE_CON, CODE_GET, random_msg_id(), token, options)
    code_str, payload, opts = send_and_parse(target, port, pkt)

    if code_str is None:
        print(f"[ ] No risposta da {target}:{port}/udp")
        return []

    print(f"    Risposta: {code_str} | {len(payload) if payload else 0} bytes payload")

    resources = []
    if payload:
        payload_str = payload.decode('utf-8', errors='replace')
        print(f"[FOUND:HIGH]  .well-known/core accessibile (no auth)")
        print(f"    Link-format:\n{payload_str}")
        # Parse link-format: </path>;rt="...";...
        for m in re.finditer(r'<([^>]+)>', payload_str):
            path = m.group(1)
            resources.append(path)
            attrs = ""
            # Check for rt, if, ct attributes
            attr_m = re.search(rf'{re.escape(path)}>([^,<]*)', payload_str)
            if attr_m:
                attrs = attr_m.group(1).strip(';')
            print(f"    Resource: {path} {attrs}")
            # Flag sensibili
            if any(k in path.lower() for k in ['auth', 'config', 'admin', 'pass', 'key', 'secret']):
                print(f"[FOUND:CRITICAL] Risorsa sensibile CoAP: {path}")

    return resources

def action_get(target, port, path):
    """GET risorsa specifica"""
    path = path.lstrip('/')
    parts = path.split('/') if path else ['']
    token = random_token()
    options = [(OPT_URI_HOST, target)]
    for part in parts:
        if part:
            options.append((OPT_URI_PATH, part))
    pkt = build_coap_packet(TYPE_CON, CODE_GET, random_msg_id(), token, options)
    code_str, payload, opts = send_and_parse(target, port, pkt)
    if code_str:
        print(f"    GET /{path} → {code_str}")
        if payload:
            try:
                print(f"    Payload: {payload.decode('utf-8', errors='replace')[:200]}")
            except Exception:
                print(f"    Payload (hex): {payload.hex()[:80]}")
        if "Unauthorized" in code_str or "Forbidden" in code_str:
            print(f"[FOUND:MEDIUM] Risorsa protetta: /{path} ({code_str})")
        elif "Content" in code_str or "Created" in code_str:
            print(f"[FOUND:HIGH]   Risorsa accessibile: /{path} ({code_str})")
    else:
        print(f"    GET /{path} → no risposta")

def action_put(target, port, path, payload_str):
    """PUT test resource injection"""
    path = path.lstrip('/')
    parts = path.split('/') if path else ['test']
    token = random_token()
    options = [(OPT_URI_HOST, target)]
    for part in parts:
        if part:
            options.append((OPT_URI_PATH, part))
    options.append((OPT_CONTENT_FORMAT, 0))  # text/plain

    payload = payload_str.encode('utf-8') if payload_str else b'exa-dune-probe'
    pkt = build_coap_packet(TYPE_CON, CODE_PUT, random_msg_id(), token, options, payload)
    code_str, resp_payload, opts = send_and_parse(target, port, pkt)
    if code_str:
        print(f"    PUT /{path} → {code_str}")
        if "Created" in code_str or "Changed" in code_str:
            print(f"[FOUND:CRITICAL] CoAP PUT riuscito senza auth: /{path} ({code_str})")
        elif "Unauthorized" in code_str or "Forbidden" in code_str:
            print(f"[ ]              PUT negato: /{path} ({code_str})")
        elif "Method Not Allowed" in code_str:
            print(f"[ ]              PUT non supportato: /{path}")
    else:
        print(f"    PUT /{path} → no risposta")

def action_observe(target, port, path, max_notif=5):
    """Observe resource (notifiche push)"""
    path = path.lstrip('/')
    parts = path.split('/') if path else ['']
    token = random_token()
    options = [(OPT_URI_HOST, target), (OPT_OBSERVE, 0)]
    for part in parts:
        if part:
            options.append((OPT_URI_PATH, part))
    pkt = build_coap_packet(TYPE_CON, CODE_GET, random_msg_id(), token, options)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    print(f"[*] CoAP Observe /{path} — attendo fino a {max_notif} notifiche (timeout 10s ciascuna)")
    try:
        sock.sendto(pkt, (target, port))
        for i in range(max_notif):
            try:
                data, _ = sock.recvfrom(4096)
                code_str, payload, opts = parse_coap_response(data)
                obs_seq = opts.get(OPT_OBSERVE)
                print(f"    Notifica {i+1}: {code_str} | obs_seq={obs_seq} | {len(payload) if payload else 0} bytes")
                if payload:
                    try:
                        print(f"    {payload.decode('utf-8', errors='replace')[:100]}")
                    except Exception:
                        pass
                if i == 0 and ("Content" in (code_str or "")):
                    print(f"[FOUND:MEDIUM] Observe accettato su /{path}")
            except socket.timeout:
                print(f"    Timeout dopo {i} notifiche")
                break
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="CoAP Scanner & Fuzzer")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=5683)
    parser.add_argument("--action", choices=["discover", "get", "put", "observe"],
                        default="discover")
    parser.add_argument("--path", default=".well-known/core")
    parser.add_argument("--payload", default="exa-dune-probe")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    print(f"[*] CoAP Scan — {args.target}:{args.port}/UDP | Action: {args.action}")

    if args.action == "discover":
        resources = action_discover(args.target, args.port)
        if resources:
            print(f"\n[*] Probe risorse trovate:")
            for res in resources[:10]:
                action_get(args.target, args.port, res)
    elif args.action == "get":
        action_get(args.target, args.port, args.path)
    elif args.action == "put":
        action_put(args.target, args.port, args.path, args.payload)
    elif args.action == "observe":
        action_observe(args.target, args.port, args.path)

if __name__ == "__main__":
    main()
