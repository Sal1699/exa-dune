#!/usr/bin/env python3
"""
sip_enum.py — SIP User Enumeration
Tecniche: REGISTER (401/403 diff), OPTIONS per-extension, timing analysis
Uso: python3 sip_enum.py <target> [--port 5060] [--range 100-500] [--method register|options] [--output file]
"""

import socket
import time
import statistics
import argparse
import sys
import random
import string
import os

def random_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def build_sip_register(target, port, extension, transport="udp"):
    call_id = random_str(16)
    tag = random_str(8)
    branch = "z9hG4bK" + random_str(10)
    attacker = "192.168.1.100"
    try:
        attacker = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    msg = (
        f"REGISTER sip:{target}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} {attacker}:5060;branch={branch};rport\r\n"
        f"From: <sip:{extension}@{target}>;tag={tag}\r\n"
        f"To: <sip:{extension}@{target}>\r\n"
        f"Call-ID: {call_id}@{attacker}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{extension}@{attacker}:5060;transport={transport.lower()}>\r\n"
        f"Max-Forwards: 70\r\n"
        f"Expires: 3600\r\n"
        f"User-Agent: exa-dune-sipenumerator/1.0\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return msg.encode()

def build_sip_options(target, port, extension, transport="udp"):
    call_id = random_str(16)
    tag = random_str(8)
    branch = "z9hG4bK" + random_str(10)
    attacker = "192.168.1.100"
    try:
        attacker = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    msg = (
        f"OPTIONS sip:{extension}@{target} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} {attacker}:5060;branch={branch};rport\r\n"
        f"From: <sip:probe@{attacker}>;tag={tag}\r\n"
        f"To: <sip:{extension}@{target}>\r\n"
        f"Call-ID: {call_id}@{attacker}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: exa-dune-sipenumerator/1.0\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return msg.encode()

def send_sip_udp(target, port, packet, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.monotonic()
        sock.sendto(packet, (target, port))
        data, _ = sock.recvfrom(4096)
        elapsed = time.monotonic() - t0
        return data.decode(errors='replace'), elapsed
    except socket.timeout:
        return None, None
    except Exception as e:
        return None, None
    finally:
        sock.close()

def send_sip_tcp(target, port, packet, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        t0 = time.monotonic()
        sock.connect((target, port))
        sock.sendall(packet)
        data = sock.recv(4096)
        elapsed = time.monotonic() - t0
        return data.decode(errors='replace'), elapsed
    except socket.timeout:
        return None, None
    except Exception as e:
        return None, None
    finally:
        sock.close()

def parse_status_code(response):
    if not response:
        return None
    lines = response.splitlines()
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None

def classify_extension(code):
    if code is None:
        return "timeout"
    if code == 401:
        return "valid"       # user esiste, chiede auth digest
    elif code == 403:
        return "blocked"     # user esiste ma è bloccato
    elif code == 404:
        return "invalid"     # user non esiste
    elif code == 200:
        return "open"        # no auth required
    elif code in (405, 400):
        return "method_not_allowed"
    elif code == 480:
        return "unavailable"
    else:
        return f"unknown({code})"

def main():
    parser = argparse.ArgumentParser(description="SIP User Enumeration")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=5060)
    parser.add_argument("--range", dest="ext_range", default="100-200",
                        help="Extension range (es. 100-500)")
    parser.add_argument("--method", choices=["register", "options"], default="register")
    parser.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    # Parse range
    try:
        start_ext, end_ext = map(int, args.ext_range.split("-"))
    except Exception:
        print(f"[ERROR] Range non valido: {args.ext_range}", file=sys.stderr)
        sys.exit(1)

    extensions = range(start_ext, end_ext + 1)
    found_valid = []
    found_blocked = []
    timings = []
    results = []

    print(f"[*] SIP Enumeration — {args.target}:{args.port}/{args.transport.upper()}")
    print(f"[*] Metodo: {args.method.upper()} | Range: {args.ext_range} ({len(extensions)} ext)")
    print()

    send_fn = send_sip_tcp if args.transport == "tcp" else send_sip_udp

    for ext in extensions:
        ext_str = str(ext)
        if args.method == "register":
            pkt = build_sip_register(args.target, args.port, ext_str, args.transport)
        else:
            pkt = build_sip_options(args.target, args.port, ext_str, args.transport)

        resp, elapsed = send_fn(args.target, args.port, pkt, args.timeout)
        code = parse_status_code(resp)
        status = classify_extension(code)

        if elapsed is not None:
            timings.append(elapsed)

        record = {"ext": ext_str, "code": code, "status": status, "elapsed": elapsed}
        results.append(record)

        if status == "valid":
            found_valid.append(ext_str)
            print(f"[FOUND:HIGH]    Ext {ext_str:>6} → {code} (USER EXISTS) [{elapsed*1000:.0f}ms]")
        elif status == "blocked":
            found_blocked.append(ext_str)
            print(f"[FOUND:MEDIUM]  Ext {ext_str:>6} → {code} (BLOCKED)     [{elapsed*1000:.0f}ms]")
        elif status == "open":
            found_valid.append(ext_str)
            print(f"[FOUND:CRITICAL] Ext {ext_str:>6} → {code} (OPEN/NO AUTH) [{elapsed*1000:.0f}ms]")
        else:
            if os.environ.get("EXA_VERBOSE"):
                print(f"[ ]             Ext {ext_str:>6} → {code or 'TIMEOUT'} ({status})")

    # Timing analysis — outlier detection (>2 stdev)
    print()
    print("[*] Timing Analysis")
    valid_timings = [t for t in timings if t is not None]
    if len(valid_timings) >= 5:
        mean_t = statistics.mean(valid_timings)
        stdev_t = statistics.stdev(valid_timings)
        threshold = mean_t + 2 * stdev_t
        print(f"    Media: {mean_t*1000:.1f}ms  StdDev: {stdev_t*1000:.1f}ms  Soglia outlier: {threshold*1000:.1f}ms")
        timing_outliers = []
        for rec in results:
            if rec["elapsed"] and rec["elapsed"] > threshold:
                timing_outliers.append(rec["ext"])
                print(f"[FOUND:INFO]  Timing outlier: ext {rec['ext']} → {rec['elapsed']*1000:.0f}ms (>{threshold*1000:.0f}ms)")
    else:
        print("    Dati insufficienti per analisi timing (<5 risposte)")

    # Summary
    print()
    print(f"[*] Risultati:")
    print(f"    Extension VALIDE (user exists): {len(found_valid)} → {', '.join(found_valid) if found_valid else 'nessuna'}")
    print(f"    Extension BLOCCATE:             {len(found_blocked)} → {', '.join(found_blocked) if found_blocked else 'nessuna'}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"# SIP Enum — {args.target}:{args.port}\n")
            f.write(f"# Metodo: {args.method.upper()} | Transport: {args.transport.upper()}\n\n")
            f.write("EXTENSION,STATUS,CODE,ELAPSED_MS\n")
            for rec in results:
                e_ms = f"{rec['elapsed']*1000:.1f}" if rec['elapsed'] else "N/A"
                f.write(f"{rec['ext']},{rec['status']},{rec['code'] or 'N/A'},{e_ms}\n")
        print(f"\n[*] Output salvato in: {args.output}")

if __name__ == "__main__":
    main()
