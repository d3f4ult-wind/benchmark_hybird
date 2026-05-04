#!/usr/bin/env bash
# =============================================================================
# run_benchmark_iptables_only.sh
# =============================================================================
# Script điều phối benchmark IPTABLES-ONLY — kịch bản đối chứng cho hybrid.
#
# CẤU TRÚC PHASE GIỐNG HỆT hybrid/run_benchmark.sh để so sánh công bằng:
#   Phase 0: Baseline                                     — 30 giây
#   Phase 1: ICMP Flood từ ns100 (bị iptables DROP)       — 60 giây
#   Phase 2: ICMP Flood + whitelist traffic hợp lệ        — 60 giây
#   Phase 3: SYN Flood từ whitelist ns50 (stateful)       — 60 giây
#   Phase 4: Tấn công tiếp tục, IP đã bị auto-blacklist   — 30 giây
#   Phase 5: Cool-down                                    — 10 giây
#
# ĐIỂM KHÁC BIỆT so với run_benchmark.sh (hybrid):
#   1. Bỏ toàn bộ hàm read_xdp_health() và cột xdp_cpu/xdp_mem trong CSV
#      → XDP không tồn tại trong kịch bản này
#   2. CSV header có thêm cột "iptables_junk_hits" để đo overhead JUNK_RULES chain
#      → Đây là dữ liệu đặc trưng của iptables-only, không có trong hybrid
#   3. Tên PHASE_NAME khác ("ICMP_FLOOD_IPT" thay vì "ICMP_FLOOD_XDP")
#      → Để phân biệt khi load cùng lúc vào analyze_benchmark.py
#   4. Thông điệp prompt_attack giải thích rõ packet đi vào kernel stack hoàn toàn
#
# Metric thu thập (mỗi 1 giây, từ /proc và /sys):
#   - CPU usage          (/proc/stat)
#   - Memory             (/proc/meminfo)
#   - RX/TX packets+bytes(/proc/net/dev)
#   - IRQ rate           (/proc/interrupts)
#   - Conntrack count    (/proc/sys/net/netfilter/nf_conntrack_count)
#   - Iptables hits      (iptables -L BLACKLIST_CHECK + JUNK_RULES)
#
# Yêu cầu:
#   - setup_iptables_only.sh đã chạy trước
#   - Attacker đã setup.sh (namespace ns10, ns50, ns100)
#   - Victim đang chạy Nginx port 80
#   - Chạy với root
#
# Cách chạy:
#   sudo bash run_benchmark_iptables_only.sh 2>&1 | tee /tmp/benchmark_ipt_only.log
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────
# Cấu hình — giống hệt hybrid để so sánh công bằng
# ─────────────────────────────────────────
IFACE="${IFACE:-enp0s8}"
TARGET_IP="${TARGET_IP:-10.10.2.2}"
FLOOD_ATTACKER_IP="10.10.1.100"    # ns100 — ICMP flood, ở hybrid bị XDP DROP, ở đây bị iptables JUNK_RULES DROP
STEALTH_ATTACKER_IP="10.10.1.50"   # ns50  — whitelist, SYN flood Phase 3
WHITELIST_CLIENT_IP="10.10.1.10"   # ns10  — client hợp lệ

CSV_DIR="${CSV_DIR:-/tmp/benchmark_results}"
RUN_ID="ipt_only_$(date '+%Y%m%d_%H%M%S')"  # Prefix "ipt_only_" để phân biệt với hybrid khi so sánh
CSV_FILE="$CSV_DIR/${RUN_ID}_metrics.csv"
EVENT_FILE="$CSV_DIR/${RUN_ID}_events.csv"

SAMPLE_INTERVAL=1  # giây — giống hybrid

# Duration từng phase — giữ nguyên như hybrid
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

read_conntrack() {
    cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0"
}

# Đọc hit count của BLACKLIST_CHECK chain — giống hàm trong hybrid
read_iptables_blacklist_hits() {
    iptables -L BLACKLIST_CHECK -n -v 2>/dev/null \
        | awk 'NR==4 {
            val = $1
            if (val ~ /G/) { gsub(/G/, "", val); val = val * 1000000000 }
            else if (val ~ /M/) { gsub(/M/, "", val); val = val * 1000000 }
            else if (val ~ /K/) { gsub(/K/, "", val); val = val * 1000 }
            print val + 0
        }'
}

# Đọc tổng số packet đã duyệt qua JUNK_RULES chain
# → Chỉ có trong iptables-only, không có trong hybrid (hybrid dùng XDP map)
# → Số liệu này phản ánh trực tiếp overhead của 1000-rule lookup trong iptables
read_iptables_junk_hits() {
    # Lấy counter của chain JUNK_RULES (dòng header "Chain JUNK_RULES" có policy/refs)
    # Dùng iptables -L JUNK_RULES -n -v -x và lấy tổng pkts tất cả rules
    iptables -L JUNK_RULES -n -v -x 2>/dev/null \
        | awk 'NR>2 {sum += $1} END {print sum+0}'
}

log_event() {
    local ts_ms
    ts_ms=$(elapsed_ms)
    echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,\"$*\"" >> "$EVENT_FILE"
    log "EVENT [Phase $CURRENT_PHASE]: $*"
}

# ─────────────────────────────────────────
# Khởi tạo CSV
# Lưu ý: Bỏ cột xdp_cpu_percent và xdp_mem_mb (không có XDP)
#         Thêm cột iptables_junk_hits (đặc trưng của iptables-only)
# → Cấu trúc này vẫn tương thích với analyze_benchmark.py vì script đó
#   chỉ dùng các cột có tên khớp, các cột thừa/thiếu sẽ bị bỏ qua/NaN
# ─────────────────────────────────────────
init_csv() {
    log "Khởi tạo CSV: $CSV_FILE"
    cat > "$CSV_FILE" << 'CSV_HEADER'
timestamp_ms,phase,phase_name,cpu_percent,mem_mb,rx_packets_delta,tx_packets_delta,rx_bytes_delta,tx_bytes_delta,irq_delta,conntrack_count,iptables_blacklist_hits,iptables_junk_hits
CSV_HEADER

    cat > "$EVENT_FILE" << 'EV_HEADER'
timestamp_ms,phase,phase_name,description
EV_HEADER
}

# ─────────────────────────────────────────
# Prompt tương tác — giống hybrid nhưng có note rõ "không có XDP"
# ─────────────────────────────────────────
prompt_attack() {
    local attack_cmd="$1"
    echo ""
    echo "============================================================"
    echo "[!] HÃY CHUYỂN SANG MÁY ATTACKER VÀ CHẠY LỆNH SAU:"
    echo -e "\e[1;33m    $attack_cmd\e[0m"
    echo "------------------------------------------------------------"
    echo "    [i] Chế độ: iptables-only — packet sẽ đi vào kernel stack"
    echo "        đầy đủ, duyệt qua JUNK_RULES (999 rules) trước khi DROP."
    echo "        Dự kiến CPU và IRQ cao hơn so với hybrid."
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận đã bắt đầu tấn công..." -r
    echo "[+] Đã xác nhận. Bắt đầu thu thập metric..."
}

stop_attack_prompt() {
    echo ""
    echo "============================================================"
    echo "[!] HÃY DỪNG TẤN CÔNG TRÊN MÁY ATTACKER (Ctrl+C)."
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận đã dừng tấn công..." -r
    echo "[+] Đã xác nhận dừng tấn công."
}

# ─────────────────────────────────────────
# Vòng lặp thu thập metric — logic giống hybrid, bỏ phần XDP health
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

        local mem_mb conntrack blacklist_hits junk_hits
        mem_mb=$(read_mem_mb)
        conntrack=$(read_conntrack)
        blacklist_hits=$(read_iptables_blacklist_hits)
        junk_hits=$(read_iptables_junk_hits)  # Chỉ có ở iptables-only

        local ts_ms
        ts_ms=$(elapsed_ms)

        # Ghi CSV — không có cột xdp_cpu/xdp_mem, có thêm iptables_junk_hits
        echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,$cpu_pct,$mem_mb,$delta_rx,$delta_tx,$delta_rxb,$delta_txb,$delta_irq,$conntrack,$blacklist_hits,$junk_hits" \
            >> "$CSV_FILE"

        prev_cpu="$curr_cpu"
        prev_net_stats="$curr_net_stats"
        prev_irq="$curr_irq"
    done
}

# ─────────────────────────────────────────
# In summary sau khi benchmark xong — giống hybrid nhưng không có XDP stats
# ─────────────────────────────────────────
print_summary() {
    log ""
    log "============================================================"
    log " SUMMARY BENCHMARK — IPTABLES-ONLY"
    log "============================================================"

    # Đọc CSV và tính mean/max theo phase bằng awk
    awk -F',' '
    NR==1 { next }  # bỏ header
    {
        phase=$2
        cpu=$4
        rx=$6
        ct=$11
        irq=$10

        count[phase]++
        sum_cpu[phase]  += cpu
        sum_rx[phase]   += rx
        sum_ct[phase]   += ct
        sum_irq[phase]  += irq
        if (cpu > max_cpu[phase]) max_cpu[phase] = cpu
    }
    END {
        phase_names[0]="Baseline"
        phase_names[1]="ICMP Flood (iptables JUNK_RULES DROP)"
        phase_names[2]="Flood + Whitelist Traffic"
        phase_names[3]="SYN Flood (Stateful Detected)"
        phase_names[4]="Post-Blacklist"
        phase_names[5]="Cool-down"

        for (p=0; p<=5; p++) {
            if (count[p] == 0) continue
            printf "Phase %d: %s\n", p, phase_names[p]
            printf "  Duration    : ~%ds (%d samples)\n", count[p], count[p]
            printf "  CPU mean/max: %.1f%% / %.1f%%\n", sum_cpu[p]/count[p], max_cpu[p]
            printf "  RX pkt/s avg: %.0f\n",  sum_rx[p]/count[p]
            printf "  Conntrack avg: %.0f\n",  sum_ct[p]/count[p]
            printf "  IRQ/s avg   : %.0f\n\n", sum_irq[p]/count[p]
        }
    }
    ' "$CSV_FILE"

    log "============================================================"
    log "[+] BENCHMARK IPTABLES-ONLY HOÀN TẤT"
    log "    Metrics : $CSV_FILE"
    log "    Events  : $EVENT_FILE"
    log ""
    log "    So sánh với hybrid bằng lệnh:"
    log "    python3 analyze_benchmark.py <hybrid_metrics.csv> <hybrid_events.csv>"
    log "    python3 analyze_benchmark.py $CSV_FILE $EVENT_FILE"
    log "============================================================"
}

# ─────────────────────────────────────────
# MAIN — Điều phối 6 phase
# Cấu trúc giống hệt hybrid để số liệu có thể so sánh trực tiếp
# ─────────────────────────────────────────
main() {
    init_csv

    log "============================================================"
    log " BENCHMARK: iptables-only (KHÔNG có XDP)"
    log " Run ID   : $RUN_ID"
    log " Interface: $IFACE"
    log " Target   : $TARGET_IP"
    log " CSV      : $CSV_FILE"
    log " [i] Kịch bản đối chứng — packet đi vào kernel stack đầy đủ"
    log "============================================================"
    log_event "Benchmark iptables-only khởi động"

    # ── Phase 0: Baseline ──────────────────────────────────────────
    CURRENT_PHASE=0; PHASE_NAME="BASELINE"
    log "=== Phase 0: BASELINE (${PHASE_0_DUR}s) ==="
    log_event "Phase 0 bắt đầu — không có tấn công, thu thập baseline"
    collect_metrics "$PHASE_0_DUR"
    log_event "Phase 0 kết thúc"

    # ── Phase 1: ICMP Flood (iptables JUNK_RULES DROP) ─────────────
    # Khác với hybrid: KHÔNG có XDP DROP ở driver level
    # → Packet từ ns100 đi vào kernel stack → iptables FORWARD
    # → Duyệt qua JUNK_RULES (999 rules) → DROP ở rule thứ 1000
    # → Kỳ vọng: CPU và IRQ CAO HƠN NHIỀU so với hybrid Phase 1
    CURRENT_PHASE=1; PHASE_NAME="ICMP_FLOOD_IPT"
    log "=== Phase 1: ICMP FLOOD → iptables JUNK_RULES DROP (${PHASE_1_DUR}s) ==="
    log "    [i] Không có XDP — packet phải đi qua kernel stack và duyệt 1000 rules"

    ATTACK_CMD="sudo ip netns exec ns100 hping3 -1 --flood -d 120 -q $TARGET_IP"
    prompt_attack "$ATTACK_CMD"

    log_event "Phase 1 bắt đầu — ICMP flood từ ns100, iptables JUNK_RULES DROP (không có XDP)"
    collect_metrics "$PHASE_1_DUR"
    log_event "Phase 1 kết thúc"

    # ── Phase 2: ICMP Flood + Whitelist traffic ─────────────────────
    CURRENT_PHASE=2; PHASE_NAME="FLOOD_PLUS_WHITELIST"
    log "=== Phase 2: ICMP FLOOD + WHITELIST TRAFFIC (${PHASE_2_DUR}s) ==="

    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN ICMP FLOOD Ở PHASE 1."
    echo "[!] MỞ TERMINAL MỚI TRÊN MÁY ATTACKER, CHẠY:"
    echo -e "\e[1;33m    sudo bash phase2.sh\e[0m"
    echo "    (phase2.sh: ip netns exec ns10 curl mỗi 1 giây)"
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận..." -r

    log_event "Phase 2 bắt đầu — flood tiếp tục, whitelist client gửi traffic hợp lệ"
    collect_metrics "$PHASE_2_DUR"
    log_event "Phase 2 kết thúc"

    # ── Phase 3: SYN Flood từ whitelist (stateful detection) ────────
    # Giống hybrid: ns50 là whitelist IP đột ngột SYN flood
    # Iptables phát hiện qua STATEFUL_DETECT chain + hashlimit
    # Khác hybrid: không có XDP feedback daemon đẩy rule xuống XDP
    #              → auto-blacklist chỉ có iptables ipset, không có tầng XDP
    CURRENT_PHASE=3; PHASE_NAME="STATEFUL_ATTACK_DETECTED"
    log "=== Phase 3: SYN FLOOD TỪ WHITELIST IP (${PHASE_3_DUR}s) ==="
    log "    [i] Phát hiện bằng iptables hashlimit, không có XDP feedback"

    ATTACK_CMD="sudo ip netns exec ns50 hping3 --syn --flood -p 80 $TARGET_IP"
    prompt_attack "$ATTACK_CMD"

    log_event "Phase 3 bắt đầu — SYN flood từ 10.10.1.50, iptables STATEFUL_DETECT"
    collect_metrics "$PHASE_3_DUR"
    log_event "Phase 3 kết thúc"

    # ── Phase 4: Sau khi auto-blacklisted ───────────────────────────
    # Giống hybrid: IP đã vào ipset blacklist
    # Khác hybrid: blacklist chỉ ở iptables, không đẩy xuống XDP được
    #              → vẫn phải qua kernel stack và JUNK_RULES check trước
    CURRENT_PHASE=4; PHASE_NAME="POST_BLACKLIST"
    log "=== Phase 4: SAU KHI BLACKLISTED (${PHASE_4_DUR}s) ==="

    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN SYN FLOOD Ở PHASE 3."
    echo "[!] IP 10.10.1.50 đã vào iptables ipset blacklist."
    echo "    Đo hiệu suất sau blacklist (không có XDP offload)..."
    echo "============================================================"
    read -p "[?] Nhấn Enter để tiếp tục..." -r

    log_event "Phase 4 bắt đầu — tấn công tiếp tục, IP đã bị iptables blacklist (no XDP)"
    collect_metrics "$PHASE_4_DUR"
    log_event "Phase 4 kết thúc"

    # ── Phase 5: Cool-down ───────────────────────────────────────────
    CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
    log "=== Phase 5: COOL-DOWN (${PHASE_5_DUR}s) ==="

    stop_attack_prompt

    log_event "Phase 5 bắt đầu — dừng tấn công, đo hồi phục"
    collect_metrics "$PHASE_5_DUR"
    log_event "Benchmark hoàn tất"

    print_summary
}

trap 'log "Bị ngắt! Dừng benchmark..."; exit 1' INT TERM

main "$@"
