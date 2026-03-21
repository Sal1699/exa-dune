# exa-dune

> Multi-protocol penetration testing framework for IoT and VoIP environments.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple)
![License](https://img.shields.io/badge/license-MIT-green)
![Shell](https://img.shields.io/badge/shell-bash-yellow)

---

## Features

- **29 subcommands** covering every major attack surface
- **7 embedded wordlists** — works out of the box, no SecLists required
- **Automated pipeline** — scan → suggest → attack → post-exploit → PDF report
- **Intelligent attack suggestions** — maps open ports to recommended modules
- **IoT/VoIP focused** — SIP enumeration, SNMP community brute, RTSP discovery, firmware analysis
- **PDF report generation** — professional reports via weasyprint

## Supported Protocols

| Category | Protocols |
|---|---|
| Recon | nmap, DNS (AXFR + brute), HTTP headers, TLS/SSL |
| VoIP | SIP (enum + crack), RTSP |
| Auth | SSH, FTP, Telnet, HTTP, RDP, VNC, SMB |
| IoT | SNMP, MQTT, Modbus/TCP, CoAP, TFTP, IPMI, UPnP, Redis, LDAP |
| Advanced | JavaScript analysis, Firmware extraction, Post-exploitation |

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/exa-dune/main/exa-dune -o exa-dune
chmod +x exa-dune
./exa-dune --version
```

Or clone the full repository:

```bash
git clone https://github.com/YOUR_USERNAME/exa-dune.git
cd exa-dune
chmod +x exa-dune
```

## Requirements

- Kali Linux (recommended) or any Debian-based distro
- Bash 4.4+
- Root privileges
- Tools: `nmap`, `hydra`, `sipvicious`, `snmpwalk`, `nikto`, `ffuf`, `openssl`, `weasyprint`

On Kali Linux all dependencies are pre-installed except weasyprint:

```bash
pip install weasyprint
```

## Usage

```
exa-dune <subcommand> [global flags] [specific flags]
```

### Global Flags

| Flag | Description |
|---|---|
| `--target / -t` | Target IP, CIDR or hostname |
| `--output-dir / -o` | Output directory |
| `--verbose / -v` | Verbose output |
| `--dry-run` | Simulate without executing |
| `--stealth` | Low-noise mode (T2, 1 thread) |
| `--timeout N` | Per-operation timeout in seconds |

### Examples

```bash
# Full automated pipeline (scan → attack → report)
exa-dune pipeline --target 192.168.1.50 --auto --output-dir /tmp/results

# Network scan with auto-suggestions
exa-dune scan --target 192.168.1.0/24 --output-dir /tmp/scan

# SIP enumeration + PIN cracking
exa-dune sip --target 192.168.1.50 --enum --crack

# SNMP community brute force + MIB walk
exa-dune snmp --target 192.168.1.50 --walk

# Web directory fuzzing + LFI + nikto
exa-dune web --target 192.168.1.50 --port 80 --lfi --nikto

# IoT/VoIP default credentials test
exa-dune creds --target 192.168.1.50

# Generate PDF report
exa-dune report --output-dir /tmp/results --pdf
```

## Automated Pipeline

The `pipeline` subcommand runs the full pentest cycle automatically:

```bash
exa-dune pipeline --target 192.168.1.50 --auto --output-dir /tmp/results
```

**Phase 1** → nmap scan
**Phase 2** → analyze results, display prioritized attack suggestions
**Phase 3** → execute attacks in priority order
**Phase 4** → auto post-exploitation on found credentials
**Phase 5** → generate HTML + PDF report

Reuse an existing scan:

```bash
exa-dune pipeline --from-scan /tmp/scan/ --auto --output-dir /tmp/results
```

## Embedded Wordlists

exa-dune v2.0.0 includes 7 wordlist categories built directly into the script:

| Wordlist | Entries | Content |
|---|---|---|
| Users | 43 | SecLists top-usernames + IoT-specific |
| Passwords | 119 | SecLists best110 + IoT/VoIP patterns |
| Web paths | 70 | CGI paths for VoIP/camera/firmware |
| SNMP communities | 70 | Common + vendor-specific |
| LFI payloads | 29 | Path traversal patterns |
| DNS subdomains | 57 | Common subdomain names |
| IoT credentials | 65 | Vendor default user:pass pairs |

External SecLists wordlists are automatically preferred when available at `/usr/share/seclists/`.

## Subcommands

```
Recon:    scan  dns   web   http  ssl   js
VoIP:     sip   rtsp
Brute:    ssh   ftp   telnet creds rdp  vnc  smb
IoT:      snmp  mqtt  modbus redis ldap upnp tftp coap ipmi
Advanced: fw    post  auto  report pipeline
```

## Legal Notice

> This tool is intended for use **exclusively** on systems you own or have explicit written authorization to test. Unauthorized use is illegal. The authors assume no liability for misuse.

## License

MIT — see [LICENSE](LICENSE)
