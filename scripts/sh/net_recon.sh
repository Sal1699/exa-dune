#!/bin/bash
# net_recon.sh — Quick Network Reconnaissance
# Uso: ./net_recon.sh <cidr> [--output dir]

set -euo pipefail

CIDR=""
OUTDIR=""
PARALLEL_JOBS=20
TOP_PORTS=50

log()  { echo "[*] $*"; }
ok()   { echo "[OK] $*"; }
warn() { echo "[!]  $*"; }
found(){ echo "[FOUND:$1] $2"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)  OUTDIR="$2";        shift 2 ;;
        --jobs)    PARALLEL_JOBS="$2"; shift 2 ;;
        --help|-h)
            echo "Uso: $0 <cidr> [--output dir] [--jobs N]"
            echo "  cidr   : CIDR di rete (es. 192.168.1.0/24)"
            echo "  --output: directory output (default: auto)"
            echo "  --jobs  : processi paralleli nmap (default: 20)"
            exit 0 ;;
        -*)  warn "Opzione sconosciuta: $1"; exit 1 ;;
        *)   CIDR="$1"; shift ;;
    esac
done

if [[ -z "$CIDR" ]]; then
    echo "Errore: CIDR mancante"
    echo "Uso: $0 <cidr> [--output dir]"
    exit 1
fi

if [[ -z "$OUTDIR" ]]; then
    OUTDIR="/tmp/net_recon_${CIDR//\//-}_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$OUTDIR"

log "=== Net Recon — $CIDR ==="
log "Output: $OUTDIR"

# ── 1. ARP Scan ──────────────────────────────────────────────────────────────
HOSTS_FILE="$OUTDIR/live_hosts.txt"
ARP_FILE="$OUTDIR/arp_scan.txt"

if command -v arp-scan &>/dev/null; then
    log "ARP scan: $CIDR"
    arp-scan --localnet --interface="${IFACE:-eth0}" 2>/dev/null \
        | grep -E "^[0-9]+\." > "$ARP_FILE" || true
    awk '{print $1}' "$ARP_FILE" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n \
        > "$HOSTS_FILE" || true
    HOST_COUNT=$(wc -l < "$HOSTS_FILE" 2>/dev/null || echo 0)
    ok "ARP scan: $HOST_COUNT host trovati"
fi

# ── 2. Nmap ping sweep (complementa arp-scan) ────────────────────────────────
NMAP_PING_FILE="$OUTDIR/nmap_ping.txt"
log "Nmap ping sweep: $CIDR"
nmap -sn --min-parallelism "$PARALLEL_JOBS" "$CIDR" \
    -oG "$NMAP_PING_FILE" 2>/dev/null || true

grep "Up" "$NMAP_PING_FILE" 2>/dev/null \
    | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
    >> "$HOSTS_FILE" || true

sort -u "$HOSTS_FILE" -o "$HOSTS_FILE" 2>/dev/null || sort -u "$HOSTS_FILE" > /tmp/hosts_uniq.txt && mv /tmp/hosts_uniq.txt "$HOSTS_FILE"
TOTAL_HOSTS=$(wc -l < "$HOSTS_FILE")
ok "Host vivi totali: $TOTAL_HOSTS"

if [[ "$TOTAL_HOSTS" -eq 0 ]]; then
    warn "Nessun host trovato in $CIDR"
    exit 0
fi

cat "$HOSTS_FILE"
echo ""

# ── 3. Port scan per ogni host ────────────────────────────────────────────────
PORTS_FILE="$OUTDIR/all_ports.txt"
log "Port scan top-${TOP_PORTS} su $TOTAL_HOSTS host..."
> "$PORTS_FILE"

nmap --top-ports "$TOP_PORTS" \
    --min-parallelism "$PARALLEL_JOBS" \
    -sV --version-intensity 3 \
    -oG "$OUTDIR/nmap_ports.gnmap" \
    -iL "$HOSTS_FILE" \
    2>/dev/null || true

# Parsing risultati grepable
if [[ -f "$OUTDIR/nmap_ports.gnmap" ]]; then
    grep "Ports:" "$OUTDIR/nmap_ports.gnmap" | while IFS= read -r line; do
        ip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        ports=$(echo "$line" | grep -oP '(?<=Ports: ).*' || true)
        echo "$ip | $ports" >> "$PORTS_FILE"
    done
fi

# ── 4. Fingerprinting automatico ─────────────────────────────────────────────
DEVICE_FILE="$OUTDIR/device_types.txt"
> "$DEVICE_FILE"

log "Fingerprinting device type..."

classify_device() {
    local ip="$1"
    local ports_line="$2"
    local dtype="unknown"
    local proto_hints=""

    # VoIP detection
    if echo "$ports_line" | grep -qE "5060|5061|2000|4569"; then
        dtype="voip"
        proto_hints="SIP"
    fi
    if echo "$ports_line" | grep -qE "5060.*udp|udp.*5060"; then
        dtype="voip-udp"
        proto_hints="SIP/UDP"
    fi

    # IP Camera
    if echo "$ports_line" | grep -qE "554|8554|1935"; then
        dtype="ipcam-rtsp"
        proto_hints="RTSP"
    fi
    if echo "$ports_line" | grep -qE "8080|8443" && echo "$ports_line" | grep -qE "554|443"; then
        dtype="ipcam-web"
        proto_hints="HTTP+RTSP"
    fi

    # ONVIF
    if echo "$ports_line" | grep -qE "8000|8080|80.*onvif"; then
        proto_hints="$proto_hints ONVIF"
    fi

    # IoT/Embedded
    if echo "$ports_line" | grep -qE "1883|8883"; then
        dtype="mqtt-broker"
        proto_hints="MQTT"
    fi
    if echo "$ports_line" | grep -qE "502|44818|2404"; then
        dtype="ics-modbus"
        proto_hints="Modbus"
        found CRITICAL "$ip — Modbus/ICS esposto (porta ${ports_line})"
    fi
    if echo "$ports_line" | grep -qE "1900|5000"; then
        proto_hints="$proto_hints UPnP"
    fi
    if echo "$ports_line" | grep -qE "5683"; then
        dtype="coap"
        proto_hints="CoAP"
    fi

    # Router
    if echo "$ports_line" | grep -qE "80|443" && echo "$ports_line" | grep -qE "23|22"; then
        dtype="router-mgmt"
        proto_hints="HTTP+SSH/Telnet"
    fi

    # Print
    printf "%-18s %-20s %s\n" "$ip" "$dtype" "$proto_hints"
    printf "%-18s %-20s %s\n" "$ip" "$dtype" "$proto_hints" >> "$DEVICE_FILE"
}

if [[ -f "$PORTS_FILE" ]]; then
    echo ""
    printf "%-18s %-20s %s\n" "IP" "TYPE" "PROTOCOLS"
    printf "%-18s %-20s %s\n" "---" "----" "---------"
    while IFS='|' read -r ip ports_line; do
        ip=$(echo "$ip" | xargs)
        classify_device "$ip" "$ports_line"
    done < "$PORTS_FILE"
fi

# ── 5. Output compatibile con exa-dune network-sweep ─────────────────────────
SWEEP_FILE="$OUTDIR/network_sweep_results.txt"
{
    echo "# exa-dune network-sweep — $CIDR — $(date)"
    echo "# Formato: IP TYPE PORTS"
    echo ""
    while IFS='|' read -r ip ports_line; do
        ip=$(echo "$ip" | xargs)
        ports=$(echo "$ports_line" | grep -oE "[0-9]+/open" | tr '\n' ',' | sed 's/,$//')
        echo "$ip $ports"
    done < "$PORTS_FILE"
} > "$SWEEP_FILE" 2>/dev/null || true

# Summary
echo ""
ok "=== Riepilogo ==="
ok "Host vivi:    $TOTAL_HOSTS"
ok "File hosts:   $HOSTS_FILE"
ok "Port scan:    $PORTS_FILE"
ok "Device types: $DEVICE_FILE"
ok "Sweep output: $SWEEP_FILE"
ok "Suggerimento: exa-dune scan <ip> per audit approfondito"
