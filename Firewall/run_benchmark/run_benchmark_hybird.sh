#!/usr/bin/env bash
# =============================================================================
# run_benchmark.sh
# =============================================================================
# Script điều phối toàn bộ kịch bản benchmark (Chạy trên máy Firewall đang chạy XDP + iptables):
#
#   Phase 0: Baseline (không có tấn công) — 30 giây
#   Phase 1: ICMP Flood từ attacker ns100 (bị XDP DROP) — 60 giây
#   Phase 2: ICMP Flood + whitelist traffic hợp lệ (ns10, ns11) đi qua — 60 giây
#   Phase 3: Whitelist IP bất ngờ tấn công SYN flood - ns50 - (stateful) — 60 giây
#            → iptables phát hiện và chặn
#            → auto_blacklist_daemon thêm IP vào ipset
#   Phase 4: Tấn công tiếp tục nhưng IP đã bị blacklist iptables — 30 giây
#   Phase 5: Cool-down — 10 giây
#
# Metric thu thập (mỗi 1 giây):
#   - CPU usage (từ /proc/stat)
#   - Interrupt rate (từ /proc/interrupts)
#   - Network RX/TX packets và bytes (từ /proc/net/dev)
#   - Memory usage (từ /proc/meminfo)
#   - conntrack table size (từ /proc/sys/net/netfilter/)
#   - iptables rule hit counter (iptables -L -n -v)
#   - XDP health API (cpu%, memory_mb)
#
# Yêu cầu:
#   - hping3 trên máy attacker để tạo traffic tấn công
#   - curl cho XDP health API
#   - Máy attacker đã được cấu hình với các IP trong netns (ns10, ns11, ns50, ns100)
#   - Máy victim đang chạy web server trên port 80 (ví dụ bằng python3 -m http.server)
#   - Chạy với root (để đọc /proc/interrupts và iptables counters)
#
# Cách chạy:
#   sudo bash run_benchmark.sh 2>&1 | tee /tmp/benchmark_run.log
# =============================================================================

set -uo pipefail #exit on error, unset variable, or pipe failure

# ─────────────────────────────────────────
# Cấu hình — chỉnh theo lab
# ─────────────────────────────────────────
IFACE="${IFACE:-enp0s8}" # Interface trên firewall nhìn về phía attacker
XDP_API="${XDP_API:-http://localhost:8080}"
TARGET_IP="${TARGET_IP:-10.10.2.2}"           # IP của máy Victim (web server) mà attacker sẽ tấn công vào
FLOOD_ATTACKER_IP="10.10.1.100"               # Netns ns100 (ICMP Flood, bị XDP DROP)
STEALTH_ATTACKER_IP="10.10.1.50"              # Netns ns50 (whitelist, thực hiện SYN flood)
WHITELIST_CLIENT_IP="10.10.1.10"              # Netns ns10 (client hợp lệ)

CSV_DIR="${CSV_DIR:-/tmp/benchmark_results}"
RUN_ID="run_$(date '+%Y%m%d_%H%M%S')"
CSV_FILE="$CSV_DIR/${RUN_ID}_metrics.csv"
EVENT_FILE="$CSV_DIR/${RUN_ID}_events.csv"

SAMPLE_INTERVAL=1   # giây

# Duration từng phase (giây)
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
START_TIME=$(date +%s%N)   # nanoseconds
ATTACK_PIDS=()             # PID của các tiến trình tấn công

# ─────────────────────────────────────────
# Hàm tiện ích
# ─────────────────────────────────────────
log() { echo "[$(date '+%F %T')] $*"; } # Log với timestamp

elapsed_ms() { # Trả về thời gian đã trôi qua từ START_TIME tính bằng milliseconds
    local now
    now=$(date +%s%N)
    echo $(( (now - START_TIME) / 1000000 ))
}

# Đọc CPU stats từ /proc/stat (tổng hợp tất cả core)
# Trả về: user nice system idle iowait irq softirq
read_cpu_stats() {
    awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8}' /proc/stat
}

# Tính % CPU busy giữa 2 lần đọc
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

# Đọc số gói RX/TX của interface
read_net_stats() {
    # Trả về: rx_packets tx_packets rx_bytes tx_bytes
    awk -v iface="$IFACE:" '$1==iface {print $3,$11,$2,$10}' /proc/net/dev
}

# Đọc tổng số ngắt
read_irq_total() {
    awk 'NR>1 {for(i=2;i<=NF;i++) sum+=$i} END{print sum+0}' /proc/interrupts
}

# Đọc memory used (MB)
read_mem_mb() {
    local total used
    total=$(awk '/MemTotal/{print $2}' /proc/meminfo)
    local avail
    avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    echo $(( (total - avail) / 1024 ))
}

# Đọc conntrack table size (số kết nối đang theo dõi)
read_conntrack() {
    cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0"
}

# Đọc hit count của rule DROP đầu tiên trong iptables (BLACKLIST_CHECK chain)
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

# Query XDP health API
read_xdp_health() {
    local result
    result=$(curl -s --max-time 1 "$XDP_API/health" 2>/dev/null || echo '{}')
    local cpu mem
    cpu=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cpu_percent',0))" 2>/dev/null || echo "0")
    mem=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('memory_mb',0))" 2>/dev/null || echo "0")
    echo "$cpu $mem"
}

# Ghi event vào event log
log_event() {
    local ts_ms phase name description
    ts_ms=$(elapsed_ms)
    phase=$CURRENT_PHASE
    name=$PHASE_NAME
    description="$*"
    echo "$ts_ms,$phase,$name,\"$description\"" >> "$EVENT_FILE"
    log "EVENT [Phase $phase]: $description"
}

# ─────────────────────────────────────────
# Khởi tạo file CSV
# ─────────────────────────────────────────
init_csv() {
    log "Khởi tạo CSV: $CSV_FILE"
    cat > "$CSV_FILE" << 'CSV_HEADER'
timestamp_ms,phase,phase_name,cpu_percent,mem_mb,rx_packets_delta,tx_packets_delta,rx_bytes_delta,tx_bytes_delta,irq_delta,conntrack_count,iptables_blacklist_hits,xdp_cpu_percent,xdp_mem_mb
CSV_HEADER

    cat > "$EVENT_FILE" << 'EV_HEADER'
timestamp_ms,phase,phase_name,description
EV_HEADER
}

# ─────────────────────────────────────────
# Hàm tương tác với người dùng - Attacker (Prompt & Wait)
# ─────────────────────────────────────────
prompt_attack() {
    local attack_cmd="$1"
    echo ""
    echo "============================================================"
    echo "[!] HÃY CHUYỂN SANG MÁY ATTACKER VÀ CHẠY LỆNH SAU:"
    echo -e "\e[1;33m    $attack_cmd\e[0m"
    echo "============================================================"
    read -p "[?] Nhấn Enter trên máy Firewall này để xác nhận đã bắt đầu tấn công từ máy Attacker..." -r
    echo "[+] Đã xác nhận. Bắt đầu thu thập metric..."
}

stop_attack_prompt() {
    echo ""
    echo "============================================================"
    echo "[!] HÃY DỪNG TẤN CÔNG TRÊN MÁY ATTACKER (Nhấn Ctrl+C trên máy Attacker)."
    echo "============================================================"
    read -p "[?] Nhấn Enter trên máy Firewall này để xác nhận đã dừng tấn công từ máy Attacker..." -r
    echo "[+] Đã xác nhận dừng tấn công."
}

# ─────────────────────────────────────────
# Hàm dừng tất cả tiến trình tấn công (gọi khi kết thúc benchmark hoặc bị ngắt)
# ─────────────────────────────────────────
stop_attacks() {
    for pid in "${ATTACK_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    ATTACK_PIDS=()
    # Dừng hping3 trên các máy remote (giả sử dùng SSH)
    # Nếu test trên cùng máy thì comment dòng dưới
    # ssh "$FLOOD_ATTACKER_IP" "pkill hping3" 2>/dev/null || true
    # ssh "$STEALTH_ATTACKER_IP" "pkill hping3" 2>/dev/null || true
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

        # Đọc giá trị hiện tại
        curr_cpu=$(read_cpu_stats)
        curr_net_stats=$(read_net_stats)
        curr_irq=$(read_irq_total)

        # Tính delta
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

        # Đọc các metric khác
        local mem_mb conntrack iptables_hits
        mem_mb=$(read_mem_mb)
        conntrack=$(read_conntrack)
        iptables_hits=$(read_iptables_blacklist_hits)

        local xdp_cpu xdp_mem
        read xdp_cpu xdp_mem <<< "$(read_xdp_health)"

        # Ghi vào CSV
        local ts_ms
        ts_ms=$(elapsed_ms)
        echo "$ts_ms,$CURRENT_PHASE,$PHASE_NAME,$cpu_pct,$mem_mb,$delta_rx,$delta_tx,$delta_rxb,$delta_txb,$delta_irq,$conntrack,$iptables_hits,$xdp_cpu,$xdp_mem" \
            >> "$CSV_FILE"

        # Cập nhật giá trị trước
        prev_cpu="$curr_cpu"
        prev_net_stats="$curr_net_stats"
        prev_irq="$curr_irq"
    done
}

# ─────────────────────────────────────────
# MAIN — Điều phối các phase
# ─────────────────────────────────────────
main() {

    init_csv # Khởi tạo file CSV và event log

    log "============================================"
    log " BENCHMARK: XDP (stateless) + iptables (stateful)"
    log " Run ID: $RUN_ID" 
    log " Interface: $IFACE"   
    log " Target (Victim): $TARGET_IP"
    log " CSV output: $CSV_FILE"
    log "============================================"
    log_event "Benchmark khởi động"

    # ── Phase 0: Baseline ──────────────────────
    CURRENT_PHASE=0; PHASE_NAME="BASELINE"
    log "=== Phase 0: BASELINE (${PHASE_0_DUR}s) ==="
    log_event "Phase 0 bắt đầu — không có tấn công, thu thập baseline"
    collect_metrics "$PHASE_0_DUR"
    log_event "Phase 0 kết thúc"

    # ── Phase 1: ICMP Flood (XDP DROP) ─────────
    CURRENT_PHASE=1; PHASE_NAME="ICMP_FLOOD_XDP"
    log "=== Phase 1: ICMP FLOOD → XDP DROP (${PHASE_1_DUR}s) ==="
    
    ATTACK_CMD="sudo ip netns exec ns100 hping3 -1 --flood -d 120 -q $TARGET_IP"
    prompt_attack "$ATTACK_CMD"
    
    log_event "Phase 1 bắt đầu — ICMP flood từ ns100, dự kiến bị XDP DROP, thu thập metric"
    collect_metrics "$PHASE_1_DUR"
    log_event "Phase 1 kết thúc"

    # ── Phase 2: ICMP Flood + whitelist traffic ─
    CURRENT_PHASE=2; PHASE_NAME="FLOOD_PLUS_WHITELIST"
    log "=== Phase 2: ICMP FLOOD + WHITELIST TRAFFIC (${PHASE_2_DUR}s) ==="
    
    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN TẤN CÔNG ICMP FLOOD Ở PHASE 1."
    echo "[!] MỞ THÊM TERMINAL TRÊN MÁY ATTACKER VÀ CHẠY LỆNH SAU ĐỂ TẠO TRAFFIC HỢP LỆ TỪ ns10 VÀ ns11:"
    echo -e "\e[1;33m    sudo ip netns exec ns10 curl -s http://$TARGET_IP/ >/dev/null && sudo ip netns exec ns11 curl -s http://$TARGET_IP/ >/dev/null\e[0m"
    echo "    (Bạn có thể chạy lặp lại lệnh trên hoặc dùng vòng lặp for)"
    echo "============================================================"
    read -p "[?] Nhấn Enter trên máy Firewall này để xác nhận đã chạy curl..."

    log_event "Phase 2 bắt đầu — flood tiếp tục, whitelist client gửi traffic hợp lệ"
    collect_metrics "$PHASE_2_DUR"
    log_event "Phase 2 kết thúc"

    # ── Phase 3: SYN Flood từ whitelist ─────────
    CURRENT_PHASE=3; PHASE_NAME="STATEFUL_ATTACK_DETECTED"
    log "=== Phase 3: SYN FLOOD TỪ WHITELIST IP (${PHASE_3_DUR}s) ==="
    
    ATTACK_CMD="sudo ip netns exec ns50 hping3 --syn --flood -p 80 $TARGET_IP"
    prompt_attack "$ATTACK_CMD"

    log_event "Phase 3 bắt đầu — SYN flood từ whitelist IP 10.10.1.50, chờ iptables phát hiện + auto-blacklist"
    collect_metrics "$PHASE_3_DUR"
    log_event "Phase 3 kết thúc"

    # ── Phase 4: Sau khi auto-blacklisted ────────
    CURRENT_PHASE=4; PHASE_NAME="POST_BLACKLIST"
    log "=== Phase 4: SAU KHI BLACKLISTED (${PHASE_4_DUR}s) ==="
    
    echo ""
    echo "============================================================"
    echo "[!] GIỮ NGUYÊN TẤN CÔNG SYN FLOOD Ở PHASE 3."
    echo "[!] IP 10.10.1.50 đã bị daemon tự động blacklist. Đang đo hiệu suất sau blacklist..."
    echo "============================================================"
    read -p "[?] Nhấn Enter để tiếp tục..." -r

    log_event "Phase 4 bắt đầu — tấn công tiếp tục nhưng IP đã bị blacklist, kiểm tra overhead giảm"
    collect_metrics "$PHASE_4_DUR"
    log_event "Phase 4 kết thúc"

    # ── Phase 5: Cool-down ────────────────────────
    CURRENT_PHASE=5; PHASE_NAME="COOLDOWN"
    log "=== Phase 5: COOL-DOWN (${PHASE_5_DUR}s) ==="

    stop_attack_prompt # Yêu cầu người dùng dừng tấn công trên máy Attacker

    log_event "Phase 5 bắt đầu — dừng tất cả tấn công, đo hồi phục hệ thống"
    collect_metrics "$PHASE_5_DUR"
    log_event "Benchmark hoàn tất"

    log ""
    log "============================================"
    log "[+] BENCHMARK HOÀN TẤT"
    log "    Metrics: $CSV_FILE"
    log "    Events:  $EVENT_FILE"
    log "    Tổng dòng dữ liệu: $(wc -l < "$CSV_FILE")"
    log "============================================"
    log ""
    log "Chạy phân tích: python3 analyze_benchmark.py $CSV_FILE $EVENT_FILE"
}

# Trap để dọn dẹp khi Ctrl+C
trap 'log "Bị ngắt! Dừng thu thâp và dọn dẹp..."; exit 1' INT TERM

main "$@"
