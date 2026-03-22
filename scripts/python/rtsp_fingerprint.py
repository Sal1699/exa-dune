#!/usr/bin/env python3
"""
rtsp_fingerprint.py — RTSP Vendor Fingerprinting
Uso: python3 rtsp_fingerprint.py <target> [--port 554]
"""

import argparse
import socket
import random
import re
import sys

VENDOR_SIGNATURES = [
    (["Hikvision", "HIKVISION", "DS-", "IPC-HF", "DFI6"], "Hikvision", "IP Camera"),
    (["Dahua", "DH-", "DHIPCam", "dahua"], "Dahua", "NVR/DVR/Camera"),
    (["AXIS", "Axis", "axis-"], "Axis", "Communications Network Camera"),
    (["Reolink", "reolink"], "Reolink", "IP Camera"),
    (["AudioCodes", "Mediant", "MP20", "audiocodes"], "AudioCodes", "VoIP Gateway"),
    (["Commend", "ET962", "Commander", "commend"], "Commend", "Intercom/SIP Station"),
    (["Milestone", "XProtect"], "Milestone", "VMS"),
    (["Bosch", "BOSCH", "AutoDome"], "Bosch", "IP Security Camera"),
    (["Hanwha", "Samsung", "SNV-", "QNV-"], "Hanwha/Samsung", "IP Camera"),
    (["VxWorks", "Wind River"], "Generic", "Embedded (VxWorks)"),
    (["GStreamer", "Live555", "LIVE555"], "Generic", "Live555 RTSP Server"),
    (["Wowza", "wowza"], "Wowza", "Media Server"),
    (["Darwin", "DSS/"], "Apple", "Darwin Streaming Server"),
    (["Pelco", "pelco"], "Pelco", "IP Camera"),
    (["Vivotek", "VIVOTEK"], "Vivotek", "IP Camera"),
    (["Mobotix", "MOBOTIX"], "Mobotix", "IP Camera"),
    (["ACTi", "acti"], "ACTi", "IP Camera"),
    (["Sony", "SNC-"], "Sony", "IP Camera"),
    (["Panasonic", "WV-"], "Panasonic", "IP Camera"),
]

# RTSP paths per vendor
VENDOR_PATHS = {
    "Hikvision": [
        "/Streaming/Channels/1", "/Streaming/Channels/101",
        "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
        "/ISAPI/Streaming/channels/101/httpPreview",
    ],
    "Dahua": [
        "/cam/realmonitor?channel=1&subtype=0",
        "/cam/realmonitor?channel=1&subtype=1",
        "/live", "/stream",
    ],
    "Axis": [
        "/axis-media/media.amp", "/axis-media/media.amp?videocodec=h264",
        "/mpeg4/media.amp", "/mjpg/video.mjpg",
    ],
    "Reolink": [
        "/h264Preview_01_main", "/h264Preview_01_sub",
        "/preview=1&channel=0&subtype=0&proto=Onvif",
    ],
    "AudioCodes": [
        "/audio", "/stream", "/live",
    ],
    "Commend": [
        "/stream", "/live", "/video",
    ],
    "Generic": [
        "/", "/live", "/stream", "/video", "/h264",
        "/live.sdp", "/live/ch0", "/cam0_0",
        "/Streaming/Channels/1",
    ],
}

def send_rtsp_request(target, port, method, path, cseq=1, timeout=5):
    msg = (
        f"{method} rtsp://{target}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"User-Agent: exa-dune-rtsp-fingerprint/1.0\r\n"
        f"Accept: application/sdp\r\n"
        f"\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        sock.sendall(msg.encode())
        resp = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b'\r\n\r\n' in resp:
                    break
            except socket.timeout:
                break
        return resp.decode(errors='replace')
    except Exception:
        return None
    finally:
        sock.close()

def extract_headers(response):
    if not response:
        return {}
    headers = {}
    lines = response.split('\r\n')
    for line in lines[1:]:
        if ':' in line:
            key, _, val = line.partition(':')
            headers[key.strip().lower()] = val.strip()
    return headers

def fingerprint_vendor(headers, response_text):
    all_text = response_text or ""
    # Concatena tutti gli header rilevanti
    fingerprint_text = " ".join([
        headers.get("server", ""),
        headers.get("user-agent", ""),
        headers.get("public", ""),
        headers.get("via", ""),
        headers.get("x-powered-by", ""),
        all_text[:500],
    ])

    for signatures, vendor, product in VENDOR_SIGNATURES:
        for sig in signatures:
            if sig.lower() in fingerprint_text.lower():
                return vendor, product, sig

    return "Unknown", "Unknown Device", None

def extract_firmware_version(headers, response_text):
    """Cerca versione firmware in header Server: o nella risposta"""
    server = headers.get("server", "")
    # Pattern comuni: 1.2.3.4, v1.2.3, VX.Y.Z
    version_patterns = [
        r'[Vv]?(\d+\.\d+\.\d+(?:\.\d+)?)',
        r'build[\s_](\d{6,})',
        r'[Ff]irmware[\s:/]+([\w\.\-]+)',
    ]
    for pat in version_patterns:
        m = re.search(pat, server)
        if m:
            return m.group(1)
        m = re.search(pat, response_text or "")
        if m:
            return m.group(1)
    return None

def parse_sdp_info(response_text):
    """Estrae info base da SDP"""
    info = {}
    for line in (response_text or "").split('\n'):
        line = line.strip()
        if line.startswith('s='):
            info['session_name'] = line[2:]
        elif line.startswith('a=rtpmap:'):
            info.setdefault('codecs', []).append(line[9:])
        elif line.startswith('a=framerate:'):
            info['framerate'] = line[12:]
        elif line.startswith('a=cliprect:'):
            info['resolution'] = line[11:]
    return info

def probe_paths(target, port, vendor, timeout=5):
    """Testa path RTSP comuni per il vendor rilevato"""
    paths_to_test = VENDOR_PATHS.get(vendor, VENDOR_PATHS["Generic"])
    if vendor != "Generic" and "Generic" in VENDOR_PATHS:
        paths_to_test = paths_to_test + VENDOR_PATHS["Generic"]

    working = []
    print(f"[*] Probe {len(paths_to_test)} path RTSP per vendor {vendor}...")
    for path in paths_to_test:
        resp = send_rtsp_request(target, port, "DESCRIBE", path, cseq=2, timeout=timeout)
        if resp:
            status_match = re.match(r'RTSP/1\.[01] (\d+)', resp)
            if status_match:
                code = int(status_match.group(1))
                if code == 200:
                    print(f"[FOUND:HIGH]  Path RTSP accessibile (no auth): {path}")
                    working.append((path, code))
                elif code == 401:
                    print(f"[FOUND:MEDIUM] Path RTSP con auth: {path} (401)")
                    working.append((path, code))
                elif code == 403:
                    print(f"[ ]            Path RTSP vietato: {path} (403)")
                elif code != 404:
                    print(f"[ ]            {path} → {code}")
    return working

def main():
    parser = argparse.ArgumentParser(description="RTSP Vendor Fingerprinting")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=554)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    print(f"[*] RTSP Fingerprint — {args.target}:{args.port}")

    # 1. RTSP OPTIONS
    print("\n[*] Invio OPTIONS...")
    options_resp = send_rtsp_request(args.target, args.port, "OPTIONS", "*", 1, args.timeout)
    if not options_resp:
        print(f"[ ] No risposta RTSP OPTIONS da {args.target}:{args.port}")
    else:
        headers_opt = extract_headers(options_resp)
        print(f"    Server: {headers_opt.get('server', 'N/A')}")
        print(f"    Public: {headers_opt.get('public', 'N/A')}")

    # 2. RTSP DESCRIBE
    print("\n[*] Invio DESCRIBE /...")
    desc_resp = send_rtsp_request(args.target, args.port, "DESCRIBE", "/", 2, args.timeout)

    all_resp = (options_resp or "") + (desc_resp or "")
    headers_desc = extract_headers(desc_resp or "")

    # Merge headers
    merged_headers = {**extract_headers(options_resp or ""), **headers_desc}

    # 3. Fingerprint
    vendor, product, matched_sig = fingerprint_vendor(merged_headers, all_resp)
    firmware = extract_firmware_version(merged_headers, all_resp)

    print(f"\n[*] === Risultati Fingerprint ===")
    print(f"    Vendor:   {vendor}")
    print(f"    Prodotto: {product}")
    if matched_sig:
        print(f"    Firma:    {matched_sig}")
    if firmware:
        print(f"    Firmware: {firmware}")
        print(f"[FOUND:INFO]  Versione firmware esposta: {firmware}")

    server_header = merged_headers.get('server', '')
    if server_header:
        print(f"    Server header: {server_header}")

    # SDP info se presente
    if desc_resp and '\r\n\r\n' in desc_resp:
        sdp = desc_resp.split('\r\n\r\n', 1)[1]
        sdp_info = parse_sdp_info(sdp)
        if sdp_info:
            print(f"\n[*] SDP Info:")
            for k, v in sdp_info.items():
                print(f"    {k}: {v}")

    # 4. Probe path
    if vendor != "Unknown":
        print(f"\n[*] Probe path RTSP per vendor: {vendor}")
        working = probe_paths(args.target, args.port, vendor, args.timeout)
        if working:
            print(f"\n[*] Path funzionanti:")
            for p, c in working:
                status = "APERTO" if c == 200 else f"AUTH({c})"
                print(f"    rtsp://{args.target}:{args.port}{p} [{status}]")
        else:
            print("[ ] Nessun path RTSP funzionante trovato")
    else:
        print("\n[ ] Vendor non identificato — probe generic paths")
        probe_paths(args.target, args.port, "Generic", args.timeout)

if __name__ == "__main__":
    main()
