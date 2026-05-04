#!/usr/bin/env bash
# =============================================================================
# run_benchmark_xdp_only.sh
# =============================================================================
# Script điều phối benchmark XDP-ONLY — kịch bản đối chứng stateless.
#
# CẤU TRÚC PHASE GIỐNG HỆT hybrid để so sánh công bằng:
#   Phase 0: Baseline                                      — 30 giây
#   Phase 1: ICMP Flood từ ns100 (bị XDP DROP)             — 60 giây
#   Phase 2: ICMP Flood + whitelist traffic hợp lệ         — 60 giây
#   Phase 3: SYN Flood từ whitelist ns50                   — 60 giây
#            → XDP KHÔNG phát hiện được (stateless blind spot)
#            → Packet lọt thẳng vào Victim — đây là hành vi kỳ vọng
#   Phase 4: SYN Flood tiếp tục (không có blacklist)       — 30 giây
#            → Khác hybrid: không có auto-blacklist vì không có iptables
#            → CPU/conntrack sẽ KHÔNG giảm ở phase này (không có gì thay đổi)
#   Phase 5: Cool-down                                     — 10 giây
#
# ĐIỂM KHÁC BIỆT so với run_benchmark.sh (hybrid):
#   1. Conntrack luôn ~0 hoặc N/A — không có iptables stateful rule nào active
#   2. Phase 3 PHASE_NAME = "SYN_FLOOD_NO_DETECT" thay vì "STATEFUL_ATTACK_DETECTED"
#   3. Phase 4 PHASE_NAME = "SYN_FLOOD_CONTINUES" — không có blacklist để kích hoạt
#   4. Có thêm hàm read_xdp_drop_count() đọc counter từ XDP map để biết
#      bao nhiêu packet bị XDP DROP (thay thế vai trò iptables_blacklist_hits)
#   5. Vẫn query XDP health API (giống hybrid) — XDP vẫn chạy
#
# Metric CSV: giữ nguyên tên cột như hybrid để analyze_benchmark.py dùng được
#   - iptables_blacklist_hits  → luôn 0 (không có iptables) — ghi 0 vào CSV
#   - xdp_cpu_percent/xdp_mem → vẫn có (XDP đang chạy)
#   - Thêm cột: xdp_drop_count (số packet bị XDP DROP, đọc từ API)
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────
# Cấu hình — giống hệt hybrid
# ─────────────────────────────────────────
IFACE="${IFACE:-enp0s8}"
XDP_API="${XDP_API:-http://localhost:8080}"
TARGET_IP="${TARGET_IP:-10.10.2.2}"
FLOOD_ATTACKER_IP="10.10.1.100"
STEALTH_ATTACKER_IP="10.10.1.50"
WHITELIST_CLIENT_IP="10.10.1.10"

CSV_DIR="${CSV_DIR:-/tmp/benchmark_results}"
RUN_ID="xdp_only_$(date '+%Y%m%d_%H%M%S')"  # Prefix phân biệt với hybrid và iptables_only
CSV_FILE="$CSV_DIR/${RUN_ID}_metrics.csv"
EVENT_FILE="$CSV_DIR/${RUN_ID}_events.csv"

SAMPLE_INTERVAL=1

# Duration giữ nguyên như hybrid
PHASE_0_DUR=30
PHASE_1_DUR=60
PHASE_2_DUR=60
PHASE_3_DUR=60
PHASE_4_DUR=30
PHASE_5_DUR=10

mkdir -p "$CSV_DIR"

# ─────────────────────────────────────────
# Kiểm tra quyền root
# ─────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root"
    exit 1
fi

# ─────────────────────────────────────────
# Trạng thái toàn cục
# ─────────────────────────────────────────
CURRENT_PHASE=0
PHASE_NAME="INIT"
START_TIME=$(date +%s%N)

# ─────────────────────────────────────────
# Hàm tiện ích — giữ nguyên logic như hybrid
# ─────────────────────────────────────────
log() { echo "[$(date '+%F %T')] $*"; }

elapsed_ms() {
    local now
    now=$(date +%s%N)
    echo $(( (now - START_TIME) / 1000000 ))
}

read_cpu_stats() {
    awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8}' /proc/stat
}

cpu_percent() {
    local prev="$1" curr="$2"
    local -a p c
    read -ra p <<< "$prev"
    read -ra c <<< "$curr"
    local prev_idle=$(( p[3] + p[4] ))
    local curr_idle=$(( c[3] + c[4] ))
    local prev_total=0 curr_total=0
    for v in "${p[@]}"; do (( prev_total += v )); done
    for v in "${c[@]}"; do (( curr_total += v )); done
    local delta_idle=$(( curr_idle - prev_idle ))
    local delta_total=$(( curr_total - prev_total ))
    if [[ $delta_total -eq 0 ]]; then echo "0.00"; return; fi
    awk "BEGIN {printf \"%.2f\", 100.0 * (1.0 - $delta_idle / $delta_total)}"
}

read_net_stats() {
    awk -v iface="$IFACE:" '$1==iface {print $3,$11,$2,$10}' /proc/net/dev
}

read_irq_total() {
    awk 'NR>1 {for(i=2;i<=NF;i++) sum+=$i} END{print sum+0}' /proc/interrupts
}

read_mem_mb() {
    local total avail
    total=$(awk '/MemTotal/{print $2}'     /proc/meminfo)
    avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    echo $(( (total - avail) / 1024 ))
}

# Conntrack: XDP-only không dùng conntrack stateful
# Vẫn đọc để có số liệu — kỳ vọng luôn ~0 hoặc chỉ có vài entry từ SSH session
read_conntrack() {
    cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0"
}

# iptables_blacklist_hits: luôn 0 vì không có iptables
# Giữ cột này trong CSV để analyze_benchmark.py không bị lỗi thiếu cột
read_iptables_blacklist_hits() {
    echo "0"
}

# XDP health — giống hybrid, query REST API
read_xdp_health() {
    local result
    result=$(curl -s --max-time 1 "$XDP_API/health" 2>/dev/null || echo '{}')
    local cpu mem
    cpu=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cpu_percent',0))" 2>/dev/null || echo "0")
    mem=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('memory_mb',0))" 2>/dev/null || echo "0")
    echo "$cpu $mem"
}

# XDP drop count — đọc tổng số packet đã bị XDP DROP từ API
# Đây là metric đặc trưng của XDP-only: cho thấy XDP đang làm việc ở tầng driver
# Trong hybrid, số này cũng có nhưng ở đây nó là "toàn bộ" bảo vệ, không có fallback
read_xdp_drop_count() {
    local result
    result=$(curl -s --max-time 1 "$XDP_API/stats" 2>/dev/null || echo '{}')
    echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Thử các tên field phổ biến trong XDP stats API
    val = d.get('drop_count') or d.get('dropped') or d.get('total_dropped') or 0
    print(int(val))
except:
    print(0)
" 2>/dev/null || echo "0"
}

log_event() {
    local ts_ms
    ts_ms=$(elapsed_ms)
    echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,\"$*\"" >> "$EVENT_FILE"
    log "EVENT [Phase $CURRENT_PHASE]: $*"
}

# ─────────────────────────────────────────
# Khởi tạo CSV
# Header giữ nguyên như hybrid + thêm cột xdp_drop_count
# → analyze_benchmark.py đọc theo tên cột nên cột thêm không gây lỗi
# ─────────────────────────────────────────
init_csv() {
    log "Khởi tạo CSV: $CSV_FILE"
    cat > "$CSV_FILE" << 'CSV_HEADER'
timestamp_ms,phase,phase_name,cpu_percent,mem_mb,rx_packets_delta,tx_packets_delta,rx_bytes_delta,tx_bytes_delta,irq_delta,conntrack_count,iptables_blacklist_hits,xdp_cpu_percent,xdp_mem_mb,xdp_drop_count
CSV_HEADER

    cat > "$EVENT_FILE" << 'EV_HEADER'
timestamp_ms,phase,phase_name,description
EV_HEADER
}

# ─────────────────────────────────────────
# Prompt tương tác
# ─────────────────────────────────────────
prompt_attack() {
    local attack_cmd="$1"
    echo ""
    echo "============================================================"
    echo "[!] HÃY CHUYỂN SANG MÁY ATTACKER VÀ CHẠY LỆNH SAU:"
    echo -e "\e[1;33m    $attack_cmd\e[0m"
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận đã bắt đầu tấn công..." -r
    echo "[+] Đã xác nhận. Bắt đầu thu thập metric..."
}

stop_attack_prompt() {
    echo ""
    echo "============================================================"
    echo "[!] HÃY DỪNG TẤN CÔNG TRÊN MÁY ATTACKER (Ctrl+C)."
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận đã dừng..." -r
    echo "[+] Đã xác nhận dừng tấn công."
}

# ─────────────────────────────────────────
# Vòng lặp thu thập metric
# ─────────────────────────────────────────
collect_metrics() {
    local duration=$1
    local prev_cpu prev_net_stats prev_irq
    local curr_cpu curr_net_stats curr_irq
    local elapsed_phase=0

    prev_cpu=$(read_cpu_stats)
    prev_net_stats=$(read_net_stats)
    prev_irq=$(read_irq_total)

    while [[ $elapsed_phase -lt $duration ]]; do
        sleep "$SAMPLE_INTERVAL"
        (( elapsed_phase += SAMPLE_INTERVAL ))

        curr_cpu=$(read_cpu_stats)
        curr_net_stats=$(read_net_stats)
        curr_irq=$(read_irq_total)

        local cpu_pct
        cpu_pct=$(cpu_percent "$prev_cpu" "$curr_cpu")

        local prev_rx prev_tx prev_rxb prev_txb
        local curr_rx curr_tx curr_rxb curr_txb
        read prev_rx prev_tx prev_rxb prev_txb <<< "$prev_net_stats"
        read curr_rx curr_tx curr_rxb curr_txb <<< "$curr_net_stats"

        local delta_rx=$(( curr_rx  - prev_rx  ))
        local delta_tx=$(( curr_tx  - prev_tx  ))
        local delta_rxb=$(( curr_rxb - prev_rxb ))
        local delta_txb=$(( curr_txb - prev_txb ))
        local delta_irq=$(( curr_irq - prev_irq ))

        local mem_mb conntrack blacklist_hits xdp_drop
        mem_mb=$(read_mem_mb)
        conntrack=$(read_conntrack)
        blacklist_hits=$(read_iptables_blacklist_hits)  # luôn 0
        xdp_drop=$(read_xdp_drop_count)

        local xdp_cpu xdp_mem
        read xdp_cpu xdp_mem <<< "$(read_xdp_health)"

        local ts_ms
        ts_ms=$(elapsed_ms)

        echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,$cpu_pct,$mem_mb,$delta_rx,$delta_tx,$delta_rxb,$delta_txb,$delta_irq,$conntrack,$blacklist_hits,$xdp_cpu,$xdp_mem,$xdp_drop" \
            >> "$CSV_FILE"

        prev_cpu="$curr_cpu"
        prev_net_stats="$curr_net_stats"
        prev_irq="$curr_irq"
    done
}

# ─────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────
print_summary() {
    log ""
    log "============================================================"
    log " SUMMARY BENCHMARK — XDP-ONLY (stateless)"
    log "============================================================"

    awk -F',' '
    NR==1 { next }
    {
        phase=$2; cpu=$4; rx=$6; ct=$11; irq=$10
        count[phase]++
        sum_cpu[phase] += cpu; sum_rx[phase] += rx
        sum_ct[phase]  += ct;  sum_irq[phase] += irq
        if (cpu > max_cpu[phase]) max_cpu[phase] = cpu
    }
    END {
        phase_names[0]="Baseline"
        phase_names[1]="ICMP Flood (XDP DROP)"
        phase_names[2]="Flood + Whitelist Traffic"
        phase_names[3]="SYN Flood — XDP BLIND (stateless cannot detect)"
        phase_names[4]="SYN Flood tiep tuc (no blacklist)"
        phase_names[5]="Cool-down"
        for (p=0; p<=5; p++) {
            if (count[p] == 0) continue
            printf "Phase %d: %s\n", p, phase_names[p]
            printf "  CPU mean/max : %.1f%% / %.1f%%\n", sum_cpu[p]/count[p], max_cpu[p]
            printf "  RX pkt/s avg : %.0f\n",  sum_rx[p]/count[p]
            printf "  Conntrack avg: %.0f  (ky vong ~0, XDP khong dung conntrack)\n", sum_ct[p]/count[p]
            printf "  IRQ/s avg    : %.0f\n\n", sum_irq[p]/count[p]
        }
    }
    ' "$CSV_FILE"

    log "============================================================"
    log "[+] BENCHMARK XDP-ONLY HOÀN TẤT"
    log "    Metrics : $CSV_FILE"
    log "    Events  : $EVENT_FILE"
    log ""
    log "    So sánh 4 kịch bản:"
    log "    python3 analyze_benchmark.py <no_fw_metrics.csv>  <no_fw_events.csv>"
    log "    python3 analyze_benchmark.py <ipt_only_metrics.csv> <ipt_only_events.csv>"
    log "    python3 analyze_benchmark.py $CSV_FILE $EVENT_FILE"
    log "    python3 analyze_benchmark.py <hybrid_metrics.csv>  <hybrid_events.csv>"
    log "============================================================"
}

# ─────────────────────────────────────────
# MAIN — 6 phase
# ─────────────────────────────────────────
main() {
    init_csv

    log "============================================================"
    log " BENCHMARK: XDP-only (stateless, KHÔNG có iptables)"
    log " Run ID   : $RUN_ID"
    log " Interface: $IFACE"
    log " XDP API  : $XDP_API"
    log " Target   : $TARGET_IP"
    log " [i] Phase 3: SYN flood sẽ KHÔNG bị chặn — đây là hành vi kỳ vọng"
    log "============================================================"
    log_event "Benchmark XDP-only khởi động"

    # ── Phase 0: Baseline ──────────────────────────────────────────
    CURRENT_PHASE=0; PHASE_NAME="BASELINE"
    log "=== Phase 0: BASELINE (${PHASE_0_DUR}s) ==="
    log_event "Phase 0 bắt đầu — không có tấn công"
    collect_metrics "$PHASE_0_DUR"
    log_event "Phase 0 kết thúc"

    # ── Phase 1: ICMP Flood (XDP DROP — giống hybrid) ──────────────
    # XDP DROP ở driver level, CPU và IRQ kỳ vọng thấp như hybrid Phase 1
    # Đây là điểm MẠNH của XDP-only — ngang hybrid trong việc chặn stateless flood
    CURRENT_PHASE=1; PHASE_NAME="ICMP_FLOOD_XDP"
    log "=== Phase 1: ICMP FLOOD → XDP DROP (${PHASE_1_DUR}s) ==="
    log "    [i] Kỳ vọng: CPU/IRQ thấp như hybrid — XDP DROP ở driver level"

    prompt_attack "sudo ip netns exec ns100 hping3 -1 --flood -d 120 -q $TARGET_IP"

    log_event "Phase 1 bắt đầu — ICMP flood từ ns100, XDP DROP (stateless)"
    collect_metrics "$PHASE_1_DUR"
    log_event "Phase 1 kết thúc"

    # ── Phase 2: ICMP Flood + whitelist traffic ─────────────────────
    CURRENT_PHASE=2; PHASE_NAME="FLOOD_PLUS_WHITELIST"
    log "=== Phase 2: ICMP FLOOD + WHITELIST TRAFFIC (${PHASE_2_DUR}s) ==="

    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN ICMP FLOOD Ở PHASE 1."
    echo "[!] MỞ TERMINAL MỚI, CHẠY:"
    echo -e "\e[1;33m    sudo bash phase2.sh\e[0m"
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận..." -r

    log_event "Phase 2 bắt đầu — flood tiếp tục, whitelist client gửi traffic hợp lệ"
    collect_metrics "$PHASE_2_DUR"
    log_event "Phase 2 kết thúc"

    # ── Phase 3: SYN Flood từ whitelist — XDP BLIND SPOT ───────────
    # Đây là phase quan trọng nhất của kịch bản XDP-only:
    # ns50 là whitelist IP → XDP PASS → packet đến thẳng Victim
    # Không có stateful layer nào phát hiện đây là SYN flood
    # → Conntrack vẫn ~0, không có auto-blacklist, CPU trên Firewall thấp
    # → Nhưng Victim chịu toàn bộ SYN flood — đây là "điểm mù"
    CURRENT_PHASE=3; PHASE_NAME="SYN_FLOOD_NO_DETECT"
    log "=== Phase 3: SYN FLOOD TỪ WHITELIST IP — XDP KHÔNG PHÁT HIỆN (${PHASE_3_DUR}s) ==="
    log "    [!] ns50 là whitelist → XDP PASS → SYN flood đến thẳng Victim"
    log "    [!] Firewall CPU sẽ thấp nhưng Victim đang chịu tải nặng"
    log "    [!] Đây là ĐIỂM MÙ của stateless firewall — ghi nhận để so sánh với hybrid"

    echo ""
    echo "============================================================"
    echo "[!] QUAN TRỌNG: Phase này minh họa GIỚI HẠN của XDP-only."
    echo "    SYN flood từ whitelist IP sẽ KHÔNG bị chặn."
    echo "    Nếu Victim bị quá tải, dừng tấn công sớm bằng Ctrl+C trên Attacker."
    echo "============================================================"
    prompt_attack "sudo ip netns exec ns50 hping3 --syn --flood -p 80 $TARGET_IP"

    log_event "Phase 3 bắt đầu — SYN flood từ whitelist 10.10.1.50, XDP PASS (stateless blind)"
    collect_metrics "$PHASE_3_DUR"
    log_event "Phase 3 kết thúc — SYN flood KHÔNG bị phát hiện"

    # ── Phase 4: SYN Flood tiếp tục — không có blacklist ───────────
    # Khác hybrid Phase 4: không có auto-blacklist nào được kích hoạt
    # → CPU, IRQ, conntrack vẫn giữ nguyên như Phase 3 — không có cải thiện
    # → Đây là bằng chứng: hybrid Phase 4 giảm overhead nhờ iptables blacklist,
    #   còn XDP-only không có cơ chế này
    CURRENT_PHASE=4; PHASE_NAME="SYN_FLOOD_CONTINUES"
    log "=== Phase 4: SYN FLOOD TIẾP TỤC — KHÔNG CÓ BLACKLIST (${PHASE_4_DUR}s) ==="
    log "    [i] Kỳ vọng: số liệu KHÔNG giảm như hybrid Phase 4 — không có blacklist"

    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN SYN FLOOD Ở PHASE 3."
    echo "    Đo thêm 30 giây để so sánh với hybrid Phase 4 (có blacklist)."
    echo "    Kỳ vọng: số liệu giữ nguyên, không có cải thiện."
    echo "============================================================"
    read -p "[?] Nhấn Enter để tiếp tục..." -r

    log_event "Phase 4 bắt đầu — SYN flood tiếp tục, không có cơ chế blacklist nào"
    collect_metrics "$PHASE_4_DUR"
    log_event "Phase 4 kết thúc"

    # ── Phase 5: Cool-down ───────────────────────────────────────────
    CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
    log "=== Phase 5: COOL-DOWN (${PHASE_5_DUR}s) ==="

    stop_attack_prompt

    log_event "Phase 5 bắt đầu — dừng tấn công, đo hồi phục"
    collect_metrics "$PHASE_5_DUR"
    log_event "Benchmark XDP-only hoàn tất"

    print_summary
}

trap 'log "Bị ngắt! Dừng benchmark..."; exit 1' INT TERM

main "$@"
