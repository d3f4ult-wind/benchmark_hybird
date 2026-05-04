#!/usr/bin/env bash
### =============================================================================
### xdp_feedback_daemon.sh (V4 - Process Substitution + Circuit Breaker)
### =============================================================================
### Daemon theo dõi kernel log (dmesg) để phát hiện event SYN-FLOOD-DETECTED
### từ iptables, sau đó tự động:
###   1. Đưa IP tấn công vào ipset blacklist của iptables (chặn ở tầng kernel).
###   2. Xóa IP khỏi ipset whitelist (tước quyền miễn trừ).
###   3. Đẩy rule DROP chính xác (TCP/80) xuống XDP qua REST API (chặn ở tầng NIC).
###
### Cải tiến V4:
###   - Dùng Process Substitution để giữ state cho biến mảng (fix lỗi subshell).
###   - Thêm cơ chế Circuit Breaker: Nếu API gọi thất bại quá 3 lần, bỏ qua IP đó
###     để tránh làm sập hệ thống khi XDP API đang down.
### =============================================================================

set -euo pipefail

# ─────────────────────────────────────────
# Cấu hình
# ─────────────────────────────────────────
XDP_API="http://localhost:8080"
LOG_TAG="[FW-BENCH] SYN-FLOOD-DETECTED"
DAEMON_LOG="/tmp/xdp_feedback_daemon.log"

echo "[$(date '+%F %T')] XDP Feedback Daemon started (PID=$$)" | tee -a "$DAEMON_LOG"
echo "[$(date '+%F %T')] Watching for iptables log: $LOG_TAG" | tee -a "$DAEMON_LOG"

# Lưu PID để tiện dừng daemon bằng lệnh: kill $(cat /tmp/xdp_feedback_daemon.pid)
echo $$ > /tmp/xdp_feedback_daemon.pid

# ─────────────────────────────────────────
# Khai báo mảng kết hợp (Associative Arrays)
# ─────────────────────────────────────────
# PUSHED_IPS: Lưu trữ các IP đã được xử lý. Dùng như 1 cơ chế "Khóa" (Lock)
# để chống spam API khi cùng 1 IP tạo ra hàng nghìn dòng log/giây.
declare -A PUSHED_IPS

# RETRY_COUNT: Đếm số lần gọi API thất bại cho từng IP. Dùng cho Circuit Breaker.
declare -A RETRY_COUNT

# ─────────────────────────────────────────
# Vòng lặp chính - Đọc log thời gian thực
# ─────────────────────────────────────────
# QUAN TRỌNG CHO NEWBIE: 
# Thông thường người ta dùng pipe: command | while read line; do ...; done
# Tuy nhiên, trong Bash, vòng lặp 'while' sau pipe chạy ở MỘT TIẾN TRÌNH CON (subshell).
# Biến thay đổi bên trong subshell sẽ BỊ MẤT khi vòng lặp kết thúc.
# Cú pháp < <(...) (Process Substitution) giúp vòng lặp chạy ở TIẾN TRÌNH CHÍNH (main shell),
# nhờ đó mảng PUSHED_IPS và RETRY_COUNT được cập nhật đúng cách!
while read -r line; do    
    
    # Trích xuất địa chỉ IP nguồn từ dòng log iptables
    # Ví dụ dòng log: "... SRC=10.10.1.50 DST=..."
    # Cú pháp \K trong grep -oP bỏ qua chữ "SRC=", chỉ lấy phần IP phía sau.
    SRC_IP=$(echo "$line" | grep -oP 'SRC=\K[\d.]+')
    
    if [[ -n "$SRC_IP" ]]; then
        
        # BƯỚC 1: KIỂM TRA CHỐNG SPAM & CIRCUIT BREAKER
        # Nếu IP đã nằm trong mảng PUSHED_IPS (giá trị != rỗng), bỏ qua.
        # Lưu ý: IP sẽ được đưa vào mảng này nếu: 
        #   a) Đã gọi API thành công (khóa vĩnh viễn cho phiên này)
        #   b) Đã thất bại quá 3 lần (Circuit Breaker ngắt mạch, khóa vĩnh viễn)
        if [[ -n "${PUSHED_IPS[$SRC_IP]:-}" ]]; then
            continue
        fi
        
        echo "[!] Iptables detected attack from whitelist IP: $SRC_IP" | tee -a "$DAEMON_LOG"
        
        # BƯỚC 2: CẬP NHẬT IPSET CỦA IPTABLES (Lớp bảo vệ Kernel)
        # Thêm vào blacklist để iptables chặn ở rule đầu tiên (BLACKLIST_CHECK)
        ipset add xdp_iptables_blacklist "$SRC_IP" 2>/dev/null || true
        # Xóa khỏi whitelist để tước quyền miễn trụ ngay lập tức
        ipset del xdp_iptables_whitelist "$SRC_IP" 2>/dev/null || true
        
        # BƯỚC 3: KHÓA TẠM THỜI (ANTI-CONCURRENCY)
        # Đánh dấu IP này đang được xử lý TRƯỚC khi gọi API.
        # Rất quan trọng: Vì dmesg phun log cực nhanh, nếu chưa set khóa này,
        # hàng chục dòng log tiếp theo của cùng IP này sẽ-trigger hàng chục API calls đồng thời.
        PUSHED_IPS[$SRC_IP]=1
        
        # BƯỚC 4: ĐẨY RULE XUỐNG XDP (Lớp bảo vệ NIC)
        # Chuẩn hóa proto=6 (TCP) và port=80 theo đúng source code eBPF hardcode.
        # Nếu thiết lập sai (như proto=0, port=0), eBPF sẽ không match key và rule vô tác dụng.
        PAYLOAD="{\"subnet\": \"$SRC_IP/32\", \"proto\": 6, \"port\": 80, \"action\": \"DROP\"}"
        
        # Gọi REST API. curl -s: silent, -o /dev/null: bỏ qua body response,
        # -w "%{http_code}": chỉ lấy mã HTTP status trả về.
        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$XDP_API/rules" \
             -H "Content-Type: application/json" \
             -d "$PAYLOAD")
             
        # BƯỚC 5: XỬ LÝ KẾT QUẢ & CIRCUIT BREAKER
        # API chuẩn RESTful của Go trả về 201 (Created) khi tạo tài nguyên mới thành công.
        if [ "$HTTP_STATUS" -eq 201 ]; then
            echo "[+] SUCCESS: Pushed DROP rule for $SRC_IP to XDP via API!" | tee -a "$DAEMON_LOG"
            # Xóa bộ đếm retry nếu có (dù thường không có nếu thành công ngay)
            unset RETRY_COUNT[$SRC_IP] 
            # Khóa PUSHED_IPS[$SRC_IP]=1 vẫn giữ nguyên để không gọi lại API cho IP này nữa.
        else
            echo "[-] FAILED: Could not push rule to XDP (HTTP $HTTP_STATUS)" | tee -a "$DAEMON_LOG"
            
            # GỠ KHÓA TẠM THỜI: Vì API thất bại, ta phải mở khóa để lần sau gói tin của IP này
            # đến, daemon sẽ thử gọi API lại.
            unset PUSHED_IPS[$SRC_IP]
            
            # Tăng bộ đếm số lần thử lại thất bại của IP này
            RETRY_COUNT[$SRC_IP]=$(( ${RETRY_COUNT[$SRC_IP]:-0} + 1 ))
            
            # CIRCUIT BREAKER (NGẮT MẠCH):
            # Nếu thất bại quá 3 lần liên tiếp, có thể XDP API đang sập hoặc lỗi mạng.
            # Thay vì cố gắng gọi API vô ích tiêu tốn tài nguyên, ta ĐÁNH DẤU KHÓA VĨNH VIỄN
            # cho IP này (PUSHED_IPS[$SRC_IP]=1). Từ giờ IP này chỉ bị chặn bởi iptables.
            if [[ ${RETRY_COUNT[$SRC_IP]} -ge 3 ]]; then
                PUSHED_IPS[$SRC_IP]=1
                echo "[!] GAVE UP pushing $SRC_IP to XDP after 3 retries. XDP API might be down." | tee -a "$DAEMON_LOG"
            fi
        fi
    fi
# Nguồn dữ liệu: Đọc trực tiếp từ kernel ring buffer (dmesg) để tránh bị journald nuốt log.
# Dùng --decode để hiển thị mức độ log, --follow để theo dõi thời gian thực.
# grep --line-buffered bắt buộc phải có để đẩy dữ liệu ngay lập tức thay vì đợi đầy buffer.
done < <(dmesg --follow --decode 2>/dev/null | grep -F --line-buffered "$LOG_TAG")