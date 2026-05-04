#!/usr/bin/env bash
# =============================================================================
# run_benchmark_no_firewall.sh
# =============================================================================
# Benchmark NO FIREWALL — baseline tuyệt đối, thiết kế an toàn tối đa.
#
# KHÁC BIỆT CẤU TRÚC so với 3 kịch bản kia (hybrid/iptables_only/xdp_only):
#
#   1. DURATION RÚT NGẮN: 30 giây/phase tấn công (thay vì 60 giây)
#      Lý do: không có gì lọc, Victim nhận 100% flood, rủi ro sập cao hơn.
#
#   2. TẤN CÔNG TUẦN TỰ, KHÔNG CHỒNG NHAU:
#      - Phase 1: chỉ ICMP flood (không có whitelist traffic)
#      - Dừng ICMP trước khi sang Phase 2
#      - Phase 2: chỉ whitelist traffic (không có flood song song)
#      - Phase 3: chỉ SYN flood
#      Lý do: ICMP + SYN flood đồng thời không có firewall = gần như chắc chắn
#      làm Victim không phản hồi. Việc chạy tuần tự vẫn đủ để so sánh từng loại.
#
#   3. WATCHDOG chạy nền:
#      Mỗi 5 giây ping Victim 1 lần. Nếu 3 lần liên tiếp thất bại:
#        → Ghi event VICTIM_UNRESPONSIVE vào CSV
#        → Kết thúc phase hiện tại sớm (không chờ hết duration)
#        → Dừng tấn công và chuyển sang cool-down ngay
#      Lý do: bảo vệ lab, đồng thời tạo data point "Victim sập ở giây thứ X"
#      — đây là một kết quả nghiên cứu có giá trị, không phải lỗi.
#
#   4. PHASE 4 KHÔNG CÓ (chỉ có 5 phase: 0-1-2-3-5):
#      Lý do: Phase 4 trong hybrid/xdp_only có ý nghĩa vì IP đã bị blacklist
#      và overhead giảm. Với no-firewall, không có blacklist nên Phase 4
#      sẽ giống hệt Phase 3 — chạy thêm chỉ tốn thời gian và tăng rủi ro sập.
#      → analyze_benchmark.py sẽ thấy phase=4 không có data, hiển thị N/A.
#
# PHASE STRUCTURE:
#   Phase 0: Baseline                         — 30 giây
#   Phase 1: ICMP Flood (không bị lọc)        — 30 giây  [rút ngắn]
#   Phase 2: Whitelist traffic hợp lệ         — 30 giây  [không có flood đồng thời]
#   Phase 3: SYN Flood (không bị lọc)         — 30 giây  [rút ngắn]
#   Phase 5: Cool-down                        — 10 giây
#
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────
# Cấu hình
# ─────────────────────────────────────────
IFACE="${IFACE:-enp0s8}"
TARGET_IP="${TARGET_IP:-10.10.2.2}"
FLOOD_ATTACKER_IP="10.10.1.100"
STEALTH_ATTACKER_IP="10.10.1.50"
WHITELIST_CLIENT_IP="10.10.1.10"

CSV_DIR="${CSV_DIR:-/tmp/benchmark_results}"
RUN_ID="no_fw_$(date '+%Y%m%d_%H%M%S')"
CSV_FILE="$CSV_DIR/${RUN_ID}_metrics.csv"
EVENT_FILE="$CSV_DIR/${RUN_ID}_events.csv"

SAMPLE_INTERVAL=1

# Duration rút ngắn xuống 30 giây cho các phase tấn công
PHASE_0_DUR=30
PHASE_1_DUR=30   # ← 30s, không phải 60s
PHASE_2_DUR=30   # ← 30s
PHASE_3_DUR=30   # ← 30s
PHASE_5_DUR=10

# Watchdog config
WATCHDOG_INTERVAL=5       # ping Victim mỗi 5 giây
WATCHDOG_FAIL_LIMIT=3     # dừng phase sớm nếu fail liên tiếp 3 lần

mkdir -p "$CSV_DIR"

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

# File tạm để watchdog giao tiếp với vòng lặp chính
# Khi watchdog phát hiện Victim không phản hồi, nó ghi "1" vào file này
# Vòng lặp collect_metrics đọc file này mỗi giây để biết khi nào cần dừng sớm
WATCHDOG_SIGNAL_FILE="/tmp/no_fw_watchdog_signal_$$"
echo "0" > "$WATCHDOG_SIGNAL_FILE"

# ─────────────────────────────────────────
# Hàm tiện ích — giống hệt các kịch bản khác
# ─────────────────────────────────────────
log() { echo "[$(date '+%F %T')] $*"; }

elapsed_ms() {
    local now; now=$(date +%s%N)
    echo $(( (now - START_TIME) / 1000000 ))
}

read_cpu_stats() {
    awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8}' /proc/stat
}

cpu_percent() {
    local prev="$1" curr="$2"
    local -a p c
    read -ra p <<< "$prev"; read -ra c <<< "$curr"
    local prev_idle=$(( p[3] + p[4] )); local curr_idle=$(( c[3] + c[4] ))
    local prev_total=0; local curr_total=0
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

# Conntrack: không có firewall rule nên luôn ~0
# Nếu nf_conntrack không được load thì trả về 0 — đúng hành vi mong muốn
read_conntrack() {
    cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0"
}

# Không có iptables rule nào → luôn 0
read_iptables_blacklist_hits() { echo "0"; }

log_event() {
    local ts_ms; ts_ms=$(elapsed_ms)
    echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,\"$*\"" >> "$EVENT_FILE"
    log "EVENT [Phase $CURRENT_PHASE]: $*"
}

# ─────────────────────────────────────────
# WATCHDOG — chạy nền bằng background subshell
#
# Cách hoạt động:
#   1. Cứ WATCHDOG_INTERVAL giây, ping TARGET_IP 1 lần (timeout 2s)
#   2. Nếu ping thất bại, tăng bộ đếm fail_count
#   3. Nếu fail_count >= WATCHDOG_FAIL_LIMIT:
#      - Ghi event VICTIM_UNRESPONSIVE vào event log
#      - Ghi "1" vào WATCHDOG_SIGNAL_FILE để báo hiệu collect_metrics dừng sớm
#      - Reset bộ đếm về 0 để không spam signal
#   4. Nếu ping thành công, reset fail_count về 0
#
# Dùng background subshell thay vì thread riêng vì bash không có thread.
# WATCHDOG_SIGNAL_FILE là cơ chế IPC đơn giản nhất giữa subshell và main loop.
# ─────────────────────────────────────────
start_watchdog() {
    local fail_count=0
    while true; do
        sleep "$WATCHDOG_INTERVAL"

        if ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
            # Victim còn sống — reset bộ đếm
            if [[ $fail_count -gt 0 ]]; then
                log "[watchdog] Victim đã phục hồi (sau $fail_count lần fail)"
                fail_count=0
            fi
        else
            (( fail_count++ )) || true
            log "[watchdog] Victim không phản hồi (lần $fail_count/$WATCHDOG_FAIL_LIMIT)"

            if [[ $fail_count -ge $WATCHDOG_FAIL_LIMIT ]]; then
                # Ghi event vào file — dùng append để không race condition với main loop
                local ts_ms; ts_ms=$(elapsed_ms)
                echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,\"VICTIM_UNRESPONSIVE — Watchdog kết thúc phase sớm\"" >> "$EVENT_FILE"
                log "[watchdog] ⚠ VICTIM_UNRESPONSIVE — gửi tín hiệu dừng phase sớm"

                # Báo hiệu cho collect_metrics dừng vòng lặp
                echo "1" > "$WATCHDOG_SIGNAL_FILE"
                fail_count=0  # Reset để không spam khi phase tiếp theo bắt đầu
            fi
        fi
    done
}

# Khởi động watchdog trong nền, lưu PID để dọn dẹp sau
WATCHDOG_PID=""
launch_watchdog() {
    start_watchdog &
    WATCHDOG_PID=$!
    log "Watchdog khởi động (PID=$WATCHDOG_PID), ping $TARGET_IP mỗi ${WATCHDOG_INTERVAL}s"
}

# Reset signal trước mỗi phase để tránh tín hiệu cũ từ phase trước
reset_watchdog_signal() {
    echo "0" > "$WATCHDOG_SIGNAL_FILE"
}

# ─────────────────────────────────────────
# Khởi tạo CSV
# Header giống hybrid nhưng không có xdp_cpu/xdp_mem (không có XDP)
# Thêm cột "early_stop" để đánh dấu sample nào bị dừng sớm bởi watchdog
# ─────────────────────────────────────────
init_csv() {
    log "Khởi tạo CSV: $CSV_FILE"
    cat > "$CSV_FILE" << 'CSV_HEADER'
timestamp_ms,phase,phase_name,cpu_percent,mem_mb,rx_packets_delta,tx_packets_delta,rx_bytes_delta,tx_bytes_delta,irq_delta,conntrack_count,iptables_blacklist_hits,early_stop
CSV_HEADER

    cat > "$EVENT_FILE" << 'EV_HEADER'
timestamp_ms,phase,phase_name,description
EV_HEADER
}

# ─────────────────────────────────────────
# Vòng lặp thu thập metric — có kiểm tra watchdog signal
# Khác với các kịch bản khác: thêm điều kiện thoát sớm khi watchdog báo hiệu
# ─────────────────────────────────────────
collect_metrics() {
    local duration=$1
    local prev_cpu prev_net_stats prev_irq
    local curr_cpu curr_net_stats curr_irq
    local elapsed_phase=0
    local early_stop_flag=0  # 0 = bình thường, 1 = bị watchdog dừng sớm

    reset_watchdog_signal

    prev_cpu=$(read_cpu_stats)
    prev_net_stats=$(read_net_stats)
    prev_irq=$(read_irq_total)

    while [[ $elapsed_phase -lt $duration ]]; do
        sleep "$SAMPLE_INTERVAL"
        (( elapsed_phase += SAMPLE_INTERVAL ))

        # Kiểm tra watchdog signal — nếu Victim không phản hồi thì thoát sớm
        if [[ "$(cat "$WATCHDOG_SIGNAL_FILE" 2>/dev/null)" == "1" ]]; then
            log "[collect] Nhận watchdog signal — kết thúc phase sớm tại giây $elapsed_phase/$duration"
            early_stop_flag=1
            break
        fi

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

        local mem_mb conntrack
        mem_mb=$(read_mem_mb)
        conntrack=$(read_conntrack)

        local ts_ms; ts_ms=$(elapsed_ms)

        # Ghi CSV — cột early_stop = 0 bình thường, 1 nếu đây là sample cuối trước khi dừng
        echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,$cpu_pct,$mem_mb,$delta_rx,$delta_tx,$delta_rxb,$delta_txb,$delta_irq,$conntrack,0,$early_stop_flag" \
            >> "$CSV_FILE"

        prev_cpu="$curr_cpu"
        prev_net_stats="$curr_net_stats"
        prev_irq="$curr_irq"
    done

    # Trả về exit code để main biết phase kết thúc sớm hay đúng hạn
    return $early_stop_flag
}

# ─────────────────────────────────────────
# Prompt — tương tác người dùng
# ─────────────────────────────────────────
prompt_attack() {
    local attack_cmd="$1"
    echo ""
    echo "============================================================"
    echo "[!] HÃY CHUYỂN SANG MÁY ATTACKER VÀ CHẠY LỆNH SAU:"
    echo -e "\e[1;33m    $attack_cmd\e[0m"
    echo "------------------------------------------------------------"
    echo "    [i] Chế độ NO FIREWALL — packet đến thẳng Victim, không bị lọc."
    echo "    [i] Watchdog đang giám sát Victim. Nếu Victim sập, phase tự dừng."
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
}

# ─────────────────────────────────────────
# Dọn dẹp khi thoát
# ─────────────────────────────────────────
cleanup() {
    log "Dọn dẹp..."
    if [[ -n "$WATCHDOG_PID" ]]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        log "Watchdog (PID=$WATCHDOG_PID) đã dừng."
    fi
    rm -f "$WATCHDOG_SIGNAL_FILE"
}
trap 'log "Bị ngắt!"; cleanup; exit 1' INT TERM

# ─────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────
print_summary() {
    log ""
    log "============================================================"
    log " SUMMARY BENCHMARK — NO FIREWALL (baseline tuyệt đối)"
    log "============================================================"

    awk -F',' '
    NR==1 { next }
    {
        phase=$2; cpu=$4; rx=$6; ct=$11; irq=$10; es=$13
        count[phase]++
        sum_cpu[phase] += cpu; sum_rx[phase] += rx
        sum_ct[phase]  += ct;  sum_irq[phase] += irq
        if (cpu > max_cpu[phase]) max_cpu[phase] = cpu
        if (es == 1) early_stop[phase] = 1
    }
    END {
        phase_names[0]="Baseline"
        phase_names[1]="ICMP Flood (khong co firewall)"
        phase_names[2]="Whitelist Traffic (khong co flood dong thoi)"
        phase_names[3]="SYN Flood (khong co firewall)"
        phase_names[5]="Cool-down"
        for (p=0; p<=5; p++) {
            if (count[p] == 0) continue
            stop_note = (early_stop[p] == 1) ? " [EARLY STOP - VICTIM UNRESPONSIVE]" : ""
            printf "Phase %d: %s%s\n", p, phase_names[p], stop_note
            printf "  CPU mean/max : %.1f%% / %.1f%%\n", sum_cpu[p]/count[p], max_cpu[p]
            printf "  RX pkt/s avg : %.0f\n",  sum_rx[p]/count[p]
            printf "  Conntrack avg: %.0f  (ky vong ~0)\n", sum_ct[p]/count[p]
            printf "  IRQ/s avg    : %.0f\n\n", sum_irq[p]/count[p]
        }
    }
    ' "$CSV_FILE"

    log "============================================================"
    log "[+] BENCHMARK NO FIREWALL HOÀN TẤT"
    log "    Metrics : $CSV_FILE"
    log "    Events  : $EVENT_FILE"
    log "============================================================"
}

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
main() {
    init_csv

    log "============================================================"
    log " BENCHMARK: No Firewall (baseline tuyệt đối)"
    log " Run ID   : $RUN_ID"
    log " Interface: $IFACE"
    log " Target   : $TARGET_IP"
    log " [i] Tấn công TUẦN TỰ, không chồng nhau — an toàn hơn"
    log " [i] Duration mỗi phase tấn công: 30s (thay vì 60s)"
    log " [i] Watchdog: ping $TARGET_IP mỗi ${WATCHDOG_INTERVAL}s, dừng sớm nếu fail x$WATCHDOG_FAIL_LIMIT"
    log "============================================================"
    log_event "Benchmark no-firewall khởi động"

    # Khởi động watchdog nền
    launch_watchdog

    # ── Phase 0: Baseline ──────────────────────────────────────────
    CURRENT_PHASE=0; PHASE_NAME="BASELINE"
    log "=== Phase 0: BASELINE (${PHASE_0_DUR}s) ==="
    log_event "Phase 0 bắt đầu"
    collect_metrics "$PHASE_0_DUR" || true
    log_event "Phase 0 kết thúc"

    # ── Phase 1: ICMP Flood — chỉ một mình, không có traffic hợp lệ đồng thời ──
    # Lý do không chồng traffic hợp lệ: với no-firewall, ICMP flood đã đủ để
    # gây áp lực. Thêm curl traffic chỉ làm phức tạp thêm, không tăng giá trị đo.
    CURRENT_PHASE=1; PHASE_NAME="ICMP_FLOOD_NO_FW"
    log "=== Phase 1: ICMP FLOOD — không có firewall (${PHASE_1_DUR}s) ==="
    log "    [i] Kỳ vọng: RX pkt/s cao, CPU cao hơn baseline vì kernel phải xử lý mọi packet"
    log "    [i] IRQ cao — không có XDP để hấp thụ interrupt trước"

    prompt_attack "sudo ip netns exec ns100 hping3 -1 --flood -d 120 -q $TARGET_IP"

    log_event "Phase 1 bắt đầu — ICMP flood từ ns100, không có firewall"
    if ! collect_metrics "$PHASE_1_DUR"; then
        log_event "Phase 1 kết thúc sớm do Victim không phản hồi"
        log "[!] Victim không phản hồi ở Phase 1. Dừng tấn công và chuyển sang cool-down."
        stop_attack_prompt
        CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
        log_event "Phase 5 bắt đầu — dừng sớm do Victim sập"
        collect_metrics "$PHASE_5_DUR" || true
        log_event "Benchmark kết thúc sớm"
        print_summary
        cleanup
        exit 0
    fi
    log_event "Phase 1 kết thúc"

    # Dừng ICMP flood trước khi sang Phase 2
    stop_attack_prompt
    log_event "ICMP flood dừng — chờ hệ thống ổn định 5 giây"
    sleep 5

    # ── Phase 2: Whitelist traffic — không có flood đồng thời ──────
    # Trong hybrid/iptables_only, Phase 2 chạy flood + whitelist traffic cùng lúc.
    # Ở đây chỉ đo whitelist traffic thuần để tránh Victim sập.
    # Giá trị của phase này: xem CPU/IRQ khi chỉ có traffic hợp lệ, không có gì can thiệp.
    CURRENT_PHASE=2; PHASE_NAME="WHITELIST_TRAFFIC_ONLY"
    log "=== Phase 2: WHITELIST TRAFFIC (không có flood đồng thời) (${PHASE_2_DUR}s) ==="
    log "    [i] Khác các kịch bản khác: không có flood song song vì an toàn hơn"

    echo ""
    echo "============================================================"
    echo "[!] CHẠY TRAFFIC HỢP LỆ TỪ ns10:"
    echo -e "\e[1;33m    sudo bash phase2.sh\e[0m"
    echo "============================================================"
    read -p "[?] Nhấn Enter để xác nhận..." -r

    log_event "Phase 2 bắt đầu — chỉ whitelist traffic, không có flood"
    if ! collect_metrics "$PHASE_2_DUR"; then
        log_event "Phase 2 kết thúc sớm"
        stop_attack_prompt
        CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
        collect_metrics "$PHASE_5_DUR" || true
        print_summary; cleanup; exit 0
    fi
    log_event "Phase 2 kết thúc"

    stop_attack_prompt
    sleep 5

    # ── Phase 3: SYN Flood — không có firewall ──────────────────────
    # Đây là phase nguy hiểm nhất: SYN flood đến thẳng Victim.
    # Không có conntrack để limit, không có hashlimit, không có syncookies trên Firewall.
    # Victim chỉ có tcp_syncookies=1 (đã bật trong setup) để tự bảo vệ.
    # Watchdog sẽ dừng sớm nếu Victim sập.
    CURRENT_PHASE=3; PHASE_NAME="SYN_FLOOD_NO_FW"
    log "=== Phase 3: SYN FLOOD — không có firewall (${PHASE_3_DUR}s) ==="
    log "    [!] Phase nguy hiểm nhất — Victim chỉ có tcp_syncookies tự bảo vệ"
    log "    [!] Watchdog đang active — sẽ dừng sớm nếu Victim không phản hồi"

    prompt_attack "sudo ip netns exec ns50 hping3 --syn --flood -p 80 $TARGET_IP"

    log_event "Phase 3 bắt đầu — SYN flood từ ns50, không có firewall"
    if ! collect_metrics "$PHASE_3_DUR"; then
        log_event "Phase 3 kết thúc sớm — Victim không phản hồi (kết quả có giá trị nghiên cứu)"
        log ""
        log "    Ghi chú cho báo cáo: Victim sập ở Phase 3 chứng minh rằng"
        log "    no-firewall không thể chống SYN flood — ngay cả với tcp_syncookies."
        log "    Đây là data point có giá trị để so sánh với hybrid."
    else
        log_event "Phase 3 kết thúc — Victim vẫn sống sót (ghi nhận)"
    fi

    stop_attack_prompt
    sleep 5

    # ── Phase 5: Cool-down ───────────────────────────────────────────
    # Không có Phase 4 vì không có blacklist nào được kích hoạt.
    CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
    log "=== Phase 5: COOL-DOWN (${PHASE_5_DUR}s) ==="
    log "    [i] Không có Phase 4 — no-firewall không có cơ chế blacklist"

    log_event "Phase 5 bắt đầu — đo hồi phục sau khi dừng tấn công"
    collect_metrics "$PHASE_5_DUR" || true
    log_event "Benchmark no-firewall hoàn tất"

    print_summary
    cleanup
}

main "$@"
