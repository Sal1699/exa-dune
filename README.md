# exa-dune

> Multi-protocol penetration testing framework for IoT and VoIP environments.

![Version](https://img.shields.io/badge/version-3.1.1-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple)
![License](https://img.shields.io/badge/license-MIT-green)
![Shell](https://img.shields.io/badge/shell-bash-yellow)
![Subcommands](https://img.shields.io/badge/subcommands-51-orange)
![Scripts](https://img.shields.io/badge/scripts-14-red)

---

## Overview

**exa-dune** is a comprehensive bash-based penetration testing framework specialised for IoT devices, VoIP gateways, IP cameras, and industrial control systems. It wraps and orchestrates dozens of tools available on Kali Linux, adds custom Python/JS/Shell attack scripts, generates professional CVSS 3.1 PDF reports in Italian, and maintains a full SQLite assessment history.

```
╔══════════════════════════════════════════════╗
║    EXA-DUNE v3.1.1                           ║
║    Generic Network Assessment Tool           ║
╚══════════════════════════════════════════════╝
```

---

## Features

| Feature | Details |
|---|---|
| **51 subcommands** | Full coverage from recon to post-exploitation |
| **14 auxiliary scripts** | Custom Python, Node.js and Shell tools in `scripts/` |
| **Credential propagation** | Auto cross-service testing of found credentials |
| **Smart pipeline** | scan → fingerprint → attack → post-exploit → PDF report |
| **CVSS 3.1 PDF reports** | Professional Italian-language reports |
| **SQLite history** | Persistent assessment database |
| **Adaptive rate limiting** | Auto-reduces nmap rate on TCP resets (`--adaptive`) |
| **JSON output** | Machine-readable findings (`--json`) |
| **Session resume** | Resume interrupted assessments |
| **Scheduled scans** | Cron-based periodic assessments with auto-diff |
| **Auto-profiles** | `voip-gateway`, `ip-camera`, `iot-adapter` |
| **Embedded wordlists** | Works out of the box, no SecLists required |

---

## Quick Install

```bash
git clone https://github.com/Sal1699/exa-dune.git
cd exa-dune
sudo cp exa-dune /usr/local/bin/exa-dune
chmod +x /usr/local/bin/exa-dune
sudo exa-dune install          # installs tools + auxiliary scripts
exa-dune --version
```

**Single-file install (no scripts):**
```bash
curl -sL https://raw.githubusercontent.com/Sal1699/exa-dune/main/exa-dune -o /usr/local/bin/exa-dune
chmod +x /usr/local/bin/exa-dune
```

**Self-update:**
```bash
exa-dune update
```

---

## Requirements

- Kali Linux (recommended) or any Debian-based distro
- Bash 4.4+, Python 3.8+, Node.js (optional, for JS scripts)
- Root privileges for most modules

Core tools (pre-installed on Kali): `nmap`, `hydra`, `sipvicious`, `snmpwalk`, `nikto`, `gobuster`, `ffuf`, `openssl`, `testssl.sh`, `sslscan`, `mosquitto-clients`, `enum4linux`, `smbclient`

Optional Python dependencies:
```bash
pip3 install paho-mqtt scapy
```

Optional Node.js:
```bash
apt install nodejs && npm install -g ws
```

---

## Subcommands

### Recon & Scanning
| Command | Description |
|---|---|
| `scan` | Port scan + recon (nmap fast/full/UDP, searchsploit) |
| `web` | Web audit (nikto, gobuster, ffuf, nmap HTTP NSE) |
| `ssl` | TLS/SSL full audit (testssl.sh, sslscan, openssl) |
| `dns` | DNS enumeration (dig AXFR, dnsrecon, subdomain brute) |
| `js` | JavaScript analysis (endpoint/secret extraction) |
| `network-sweep` | Subnet sweep: arp-scan + auto-fingerprint + host table |

### VoIP / SIP
| Command | Description |
|---|---|
| `sip` | SIP/VoIP enumeration (svmap, svwar, svcrack) |
| `rtsp` | RTSP stream audit + Digest brute force |
| `onvif` | ONVIF/gSOAP IP camera audit |
| `sip-fuzz` | SIP fuzzing + stress test |
| `voip-enum` | Advanced VoIP: rate limit, user enum, toll fraud, TLS |

### Authentication & Brute Force
| Command | Description |
|---|---|
| `creds` | Credential brute force (hydra multiprotocol) |
| `ssh` | SSH audit + brute force (ssh-audit, hydra) |
| `ftp` | FTP audit (anon test, traversal, hydra) |
| `telnet` | Telnet banner + timing attack + brute force |
| `smb` | SMB/NetBIOS audit (enum4linux, GPP, signing check) |
| `rdp` | RDP audit + brute force + NLA/CredSSP check |
| `vnc` | VNC audit (nmap NSE, hydra) |
| `ldap` | LDAP enumeration (ldapsearch, null bind) |

### IoT / Industrial
| Command | Description |
|---|---|
| `snmp` | SNMP audit (snmpwalk, community brute, SNMPv3) |
| `mqtt` | MQTT broker audit (mosquitto, anon, wildcard subscribe) |
| `modbus` | Modbus/ICS audit (FC1-43, Unit ID enum, write PoC) |
| `coap` | CoAP IoT protocol audit (custom scanner, DTLS bypass) |
| `upnp` | UPnP/SSDP + WANIPConnection exploit |
| `tftp` | TFTP file enumeration |
| `ipmi` | IPMI/BMC audit (cipher 0, hash dump) |
| `bacnet` | BACnet/IP building automation |
| `enip` | EtherNet/IP CIP PLC audit |
| `wsd` | WS-Discovery/SSDP device enumeration |
| `mdns` | mDNS/Bonjour service discovery |
| `http` | HTTP exploitation embedded (CGI, injection, auth bypass) |
| `redis` | Redis audit + RCE check |

### Camera / Device CVE
| Command | Description |
|---|---|
| `cam-cve` | CVE scanner: Hikvision, Dahua, Axis, Reolink, AudioCodes, Commend |
| `rtmp` | RTMP stream probe (DVR/NVR) |
| `firmware` | Firmware analysis: binwalk, hardcoded creds, SUID, TLS certs |
| `config-audit` | Config file audit: creds, SNMP, hash types, private keys |

### Post-Exploitation
| Command | Description |
|---|---|
| `post` | Post-exploitation (shell, web, smb, revshell, privesc, PTH) |
| `fw` | Firewall bypass + analysis (ACK/FIN/frag/IPv6/UPnP/SIP-ALG) |

### Orchestration
| Command | Description |
|---|---|
| `auto` | Full assessment with profiles (voip-gateway, ip-camera, iot-adapter) |
| `pipeline` | Smart pipeline: scan → attack → post → PDF report |
| `resume` | Resume interrupted assessment from session.json |
| `schedule` | Periodic cron-based scans with auto-diff |

### Reporting & Utilities
| Command | Description |
|---|---|
| `report` | Generate HTML/PDF report (CVSS 3.1, Italian, CONFIDENZIALE) |
| `diff` | Differential comparison between two assessments |
| `history` | SQLite assessment history (--target, --last N, --findings ID) |
| `self-test` | Check all tool availability + optional auto-install |
| `update` | Self-update from GitHub |
| `install` | Install all missing tools + auxiliary scripts |
| `wordlists` | Download extended wordlists from SecLists on GitHub |

---

## Auto Profiles

```bash
# VoIP gateway (AudioCodes MP20x, Commend ET962, GAI-Tronics)
exa-dune auto 192.168.1.10 --profile voip-gateway

# IP camera (Axis, Reolink)
exa-dune auto 192.168.1.20 --profile ip-camera

# Generic IoT adapter
exa-dune auto 192.168.1.30 --profile iot-adapter

# Full subnet discovery + auto-profile each host
exa-dune network-sweep 192.168.1.0/24 --auto
```

---

## Auxiliary Scripts

Installed to `/usr/share/exa-dune/scripts/` via `exa-dune install`.

### Python
| Script | Description |
|---|---|
| `sip_enum.py` | SIP user enumeration via REGISTER/OPTIONS + timing analysis |
| `onvif_brute.py` | ONVIF WS-Security brute force + 14 default credential pairs |
| `modbus_rw.py` | Modbus FC1-6/43 read/write PoC (socket raw + pymodbus fallback) |
| `coap_scan.py` | CoAP client: discover/get/put/observe (no libcoap required) |
| `rtsp_fingerprint.py` | Vendor fingerprint from RTSP OPTIONS/DESCRIBE (17 vendors) |
| `mqtt_audit.py` | MQTT audit with paho-mqtt: anon connect, wildcard, JSON parse |
| `upnp_exploit.py` | UPnP IGD: GetExternalIP, AddPortMapping without auth |
| `cam_cve_batch.py` | Batch CVE scanner for IP cameras (CIDR or file input) |
| `http_iot_fuzz.py` | HTTP fuzzer: 60+ CGI paths, injection, auth bypass |
| `sip_pcap_creds.py` | Extract SIP credentials from PCAP + offline MD5 crack |

### JavaScript (Node.js)
| Script | Description |
|---|---|
| `websocket_audit.js` | WebSocket probe/auth/fuzz on 14 common paths |
| `xss_generator.js` | XSS payload generator + reflection test (incl. CVE-2019-9955) |

### Shell
| Script | Description |
|---|---|
| `voip_capture.sh` | VoIP traffic capture (tcpdump SIP+RTP) + analysis + cred extract |
| `net_recon.sh` | Quick recon: arp-scan + nmap top-50 + device fingerprint |

---

## Credential Propagation

When credentials are found during a test, exa-dune automatically tests them on other services on the same host:

```
snmp → community "public" found
ssh  → admin:admin123 found (hydra)
         └─ [propagation] admin:admin123 on SSH:22   → CRITICAL: valid
         └─ [propagation] admin:admin123 on HTTP:80  → HIGH: valid
         └─ [propagation] admin:admin123 on FTP:21   → no match
```

All credentials are stored in `creds.json` within the session directory and included in the final PDF report.

---

## Global Options

| Option | Description |
|---|---|
| `--dry-run` | Show commands without executing |
| `--stealth` | Low-noise mode (nmap -T2, reduced rate) |
| `--adaptive` | Auto-reduce rate on TCP resets detected |
| `--timeout N` | Per-module timeout in minutes |
| `--output DIR` | Override output directory |
| `--json` | Write findings.json + summary.json per module |

---

## Examples

```bash
# Quick scan + auto attack suggestions
exa-dune scan 192.168.1.1

# Full VoIP gateway assessment
exa-dune auto 192.168.1.10 --profile voip-gateway

# Full automated pipeline → PDF report
exa-dune pipeline 192.168.1.10

# Subnet sweep → auto-profile each host
exa-dune network-sweep 192.168.1.0/24 --auto

# SIP enumeration with custom extension range
exa-dune sip 192.168.1.10 --range 100-999

# Camera CVE check
exa-dune cam-cve 192.168.1.10 --vendor audiocodes
exa-dune cam-cve 192.168.1.10 --vendor hikvision

# Firmware analysis
exa-dune firmware /tmp/firmware.bin --vendor reolink

# Config file audit
exa-dune config-audit /root/pentest/configs/ --recursive

# VoIP PCAP credential extraction
python3 /usr/share/exa-dune/scripts/python/sip_pcap_creds.py capture.pcap

# Diff between two assessments
exa-dune diff /root/pentest/run_old/ /root/pentest/run_new/ --pdf

# Assessment history
exa-dune history --target 192.168.1.10 --last 5

# Scheduled weekly scan
exa-dune schedule --add --target 192.168.1.10 --cron "0 2 * * 1" --profile voip-gateway

# Resume interrupted assessment
exa-dune resume /root/pentest/exa-dune-192-168-1-10_20260322/

# Self-test + install missing tools
exa-dune self-test --install-missing
```

---

## Vendor CVE Coverage

| Vendor | CVEs / Checks |
|---|---|
| **Hikvision** | CVE-2021-36260 (RCE via /SDK/webLanguage), CVE-2017-7921 (snapshot auth bypass) |
| **Dahua** | CVE-2021-33044 (auth bypass magic packet), CVE-2017-7925 (config download) |
| **Axis** | CVE-2018-10660 (VAPIX root shell), CVE-2016-6201 (snapshot auth bypass) |
| **Reolink** | RTSP no-auth, credentials in URL |
| **AudioCodes MP20x** | CVE-2019-9955 (XSS), CVE-2016-4960 (directory traversal), default creds, SNMP exposure |
| **Commend ET962** | Default creds, CGI paths, RTSP no-auth, SIP registration bypass |

---

## Directory Structure

```
exa-dune-repo/
├── exa-dune                    # Main script (~18.600 lines)
├── scripts/
│   ├── python/                 # 10 Python attack scripts
│   ├── js/                     # 2 Node.js scripts
│   └── sh/                     # 2 Shell helpers
├── README.md
└── LICENSE
```

Output is saved to `/root/pentest/exa-dune-<target>_<timestamp>/` with subdirectories per module, a session log, `findings.txt`, `creds.json`, and `session.json`.

---

## Changelog

### v3.1.1 — 2026-03-29

**Bug fixes & improvements from live testing against Reolink IP cameras:**

| # | Area | Fix |
|---|---|---|
| 1 | `cam-cve` | Fixed unbound variable `$last_hop` → `$_last_hop` crash in traceroute check |
| 2 | `cam-cve` | False positive elimination: `_cam_check` now validates HTTP 200 response body, filtering auth-error pages |
| 3 | `cam-cve` | Hikvision CVE-2014-4880 pattern updated to match actual response (`statusValue`, `userCheckResult`) |
| 4 | `cam-cve` | Axis CVE-2018-10660 pattern updated (`<root>`, `AuthAnonymous`) |
| 5 | `cam-cve` | GENERIC-RTSP credential leak pattern tightened (`rtsp://`, `"password"`, `"credential"`, `rtspUrl`) |
| 6 | `cam-cve` | ONVIF URL fixed: was building `http://target:80:8000`, now correctly `http://target:8000` |
| 7 | `cam-cve` | RTMP false positives: now requires `codec_type` in ffprobe metadata before reporting stream |
| 8 | `cam-cve` | AudioCodes/Commend credential checks: baseline unauthenticated request comparison added |
| 9 | `cam-cve` | Vendor auto-detection: added HTML body fallback when HTTP headers lack vendor name |
| 10 | `cam-cve` | Reolink RTSP credential pattern tightened (mirrors GENERIC-RTSP fix) |
| 11 | `auto` | `prescan_context` now includes `http-title` values from nmap output for better vendor profiling |
| 12 | `rtsp` | RTSP nmap results: 401-only paths logged as INFO instead of MEDIUM false positives |
| 13 | `ssl` | SSL nmap results: filter out `disabled`/`not vulnerable` lines and cert MD5 fingerprints |
| 14 | `rtsp` | RTSP Digest brute force: per-request CSeq increment + nonce refresh every 50 attempts |
| 15 | `rtsp` | RTSP wordlist: replaced 828-entry `users-cirt.txt` with 16-entry `users-rtsp-cameras.txt` (avoids timeout) |
| 16 | `wordlists` | Added `users-rtsp-cameras.txt`: 16 camera-specific usernames for focused RTSP brute force |

---

## Legal Notice

> This tool is intended for use **exclusively** on systems you own or have explicit written authorization to test. Unauthorized use is illegal. The authors assume no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
