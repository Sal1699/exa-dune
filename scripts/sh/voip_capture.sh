#!/bin/bash
# voip_capture.sh — VoIP Traffic Capture & Analysis
# Uso: ./voip_capture.sh [--iface eth0] [--target 192.168.1.0/24] [--duration 60] [--output dir]

set -euo pipefail

IFACE="${IFACE:-eth0}"
TARGET_NET=""
DURATION=60
OUTDIR="/tmp/voip_capture_$(date +%Y%m%d_%H%M%S)"
SIP_PORTS="5060,5061"
RTP_PORT_LOW=10000
RTP_PORT_HIGH=20000

# Parse argomenti
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)    IFACE="$2";       shift 2 ;;
        --target)   TARGET_NET="$2";  shift 2 ;;
        --duration) DURATION="$2";    shift 2 ;;
        --output)   OUTDIR="$2";      shift 2 ;;
        --help|-h)
            echo "Uso: $0 [--iface eth0] [--target 192.168.1.0/24] [--duration 60] [--output dir]"
            exit 0 ;;
        *) echo "[!] Opzione sconosciuta: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTDIR"

log()  { echo "[*] $*"; }
ok()   { echo "[OK] $*"; }
warn() { echo "[!]  $*"; }

PCAP_FILE="$OUTDIR/voip_capture.pcap"

log "=== VoIP Traffic Capture ==="
log "Interface: $IFACE | Duration: ${DURATION}s | Output: $OUTDIR"

# Verifica tcpdump
if ! command -v tcpdump &>/dev/null; then
    warn "tcpdump non trovato. Installa con: apt install tcpdump"
    exit 1
fi

# Costruisci filtro tcpdump
FILTER="port ${SIP_PORTS//,/ or port } or (udp portrange ${RTP_PORT_LOW}-${RTP_PORT_HIGH})"
if [[ -n "$TARGET_NET" ]]; then
    FILTER="net $TARGET_NET and ($FILTER)"
fi

log "Filtro: $FILTER"
log "Avvio cattura tcpdump per ${DURATION}s..."

# Cattura VoIP
if [[ $EUID -ne 0 ]]; then
    warn "Attenzione: tcpdump potrebbe richiedere privilegi root"
fi

timeout "$DURATION" tcpdump -i "$IFACE" -w "$PCAP_FILE" "$FILTER" -q 2>/dev/null || true

if [[ -f "$PCAP_FILE" ]] && [[ -s "$PCAP_FILE" ]]; then
    PCAP_SIZE=$(du -h "$PCAP_FILE" | cut -f1)
    ok "PCAP catturato: $PCAP_FILE ($PCAP_SIZE)"
else
    warn "PCAP vuoto o non creato"
    exit 1
fi

# Analisi con sngrep
if command -v sngrep &>/dev/null; then
    log "Analisi con sngrep..."
    # sngrep export CSV (modalità batch)
    CSV_FILE="$OUTDIR/sip_calls.csv"
    if sngrep -I "$PCAP_FILE" -O "$OUTDIR/sngrep_export.pcap" 2>/dev/null; then
        ok "sngrep analisi completata"
    else
        # Alternativa: usa sngrep per contare chiamate
        CALL_COUNT=$(sngrep -I "$PCAP_FILE" --no-interface 2>/dev/null | grep -c "INVITE\|REGISTER" || echo 0)
        log "sngrep: ~${CALL_COUNT} messaggi SIP rilevati"
    fi
fi

# Analisi con tshark se disponibile
if command -v tshark &>/dev/null; then
    log "Analisi SIP con tshark..."
    TSHARK_SIP="$OUTDIR/sip_analysis.txt"
    tshark -r "$PCAP_FILE" -Y "sip" -T fields \
        -e frame.number -e ip.src -e ip.dst -e sip.Method \
        -e sip.From -e sip.To -e sip.Status-Code \
        > "$TSHARK_SIP" 2>/dev/null || true
    if [[ -s "$TSHARK_SIP" ]]; then
        ok "SIP analysis: $TSHARK_SIP"
        SIP_COUNT=$(wc -l < "$TSHARK_SIP")
        log "Messaggi SIP trovati: $SIP_COUNT"
        # Mostra REGISTER e INVITE
        grep -E "REGISTER|INVITE" "$TSHARK_SIP" | head -10 || true
    fi

    # Estrai stream RTP
    log "Analisi RTP stream..."
    RTP_FILE="$OUTDIR/rtp_streams.txt"
    tshark -r "$PCAP_FILE" -Y "rtp" -T fields \
        -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e rtp.ssrc \
        2>/dev/null | sort -u > "$RTP_FILE" || true
    if [[ -s "$RTP_FILE" ]]; then
        RTP_COUNT=$(wc -l < "$RTP_FILE")
        ok "Stream RTP trovati: $RTP_COUNT"
    fi
fi

# Estrai RTP con rtpbreak se disponibile
if command -v rtpbreak &>/dev/null; then
    log "Estrazione RTP stream con rtpbreak..."
    RTP_DIR="$OUTDIR/rtp_streams"
    mkdir -p "$RTP_DIR"
    rtpbreak -d "$RTP_DIR" -r "$PCAP_FILE" 2>/dev/null || true
    RTP_FILES=$(find "$RTP_DIR" -name "*.rtp" 2>/dev/null | wc -l)
    ok "Stream RTP estratti: $RTP_FILES"
fi

# Estrazione credenziali con sip_pcap_creds.py
SIP_SCRIPT_PATH=""
for p in \
    "$(dirname "$0")/../python/sip_pcap_creds.py" \
    "/usr/share/exa-dune/scripts/python/sip_pcap_creds.py" \
    "/root/pentest/exa-dune-repo/scripts/python/sip_pcap_creds.py"; do
    if [[ -f "$p" ]]; then
        SIP_SCRIPT_PATH="$p"
        break
    fi
done

if [[ -n "$SIP_SCRIPT_PATH" ]] && command -v python3 &>/dev/null; then
    log "Estrazione credenziali SIP con sip_pcap_creds.py..."
    CREDS_FILE="$OUTDIR/sip_credentials.txt"
    python3 "$SIP_SCRIPT_PATH" "$PCAP_FILE" --output "$CREDS_FILE" 2>/dev/null || true
    if [[ -f "$CREDS_FILE" ]] && [[ -s "$CREDS_FILE" ]]; then
        ok "Credenziali estratte: $CREDS_FILE"
        grep -v "^#" "$CREDS_FILE" | head -10 || true
    fi
fi

# Report finale
REPORT_FILE="$OUTDIR/voip_capture_report.txt"
{
    echo "=== VoIP Capture Report ==="
    echo "Data: $(date)"
    echo "Interface: $IFACE"
    echo "Target: ${TARGET_NET:-all}"
    echo "Duration: ${DURATION}s"
    echo ""
    echo "File PCAP: $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1))"
    echo ""
    if [[ -f "$OUTDIR/sip_analysis.txt" ]]; then
        echo "=== Messaggi SIP ==="
        head -20 "$OUTDIR/sip_analysis.txt" 2>/dev/null || true
    fi
    if [[ -f "$OUTDIR/sip_credentials.txt" ]]; then
        echo ""
        echo "=== Credenziali Trovate ==="
        grep -v "^#" "$OUTDIR/sip_credentials.txt" || true
    fi
} > "$REPORT_FILE"

ok "Report salvato: $REPORT_FILE"
ok "Output directory: $OUTDIR"
log "Per analisi interattiva: sngrep -I $PCAP_FILE"
