#!/usr/bin/env bash
# =============================================================================
# setup_no_firewall.sh
# =============================================================================
# Gỡ bỏ TOÀN BỘ lớp bảo vệ (XDP lẫn iptables) để đo baseline tuyệt đối.
#
# Vị trí trong bộ so sánh:
#   [no_firewall]  → baseline: packet đi thẳng, không có gì can thiệp  ← file này
#   iptables_only  → netfilter truyền thống
#   xdp_only       → stateless nhanh nhưng mù với TCP state
#   hybrid         → XDP + iptables, đối tượng nghiên cứu chính
#
# Mục đích đo lường:
#   - CPU/IRQ khi KHÔNG có firewall = overhead tối thiểu của hệ thống
#   - Conntrack = 0 hoàn toàn (không có rule nào kích hoạt conntrack)
#   - Đây là "trần lý thuyết" về hiệu năng: mọi kịch bản khác đều cao hơn con số này
#   - Nếu hybrid gần với no_firewall → hybrid có overhead rất thấp → luận điểm mạnh
#
# ⚠ CẢNH BÁO AN TOÀN — ĐỌC TRƯỚC KHI CHẠY:
#   1. Victim sẽ nhận TOÀN BỘ flood không bị lọc.
#      → Bật tcp_syncookies=1 trên máy Victim TRƯỚC khi chạy benchmark:
#         ssh victim "sudo sysctl -w net.ipv4.tcp_syncookies=1"
#   2. Không chạy ICMP flood và SYN flood đồng thời (khác 3 kịch bản kia).
#      → run_benchmark_no_firewall.sh đã xử lý điều này.
#   3. Duration mỗi phase được rút ngắn xuống 30 giây (thay vì 60) để giảm rủi ro.
#   4. Watchdog tự động kết thúc phase sớm nếu Victim không phản hồi.
# =============================================================================

set -euo pipefail

IFACE_IN="${IFACE_IN:-enp0s8}"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root (sudo)"
    exit 1
fi

echo "[*] Chế độ: NO FIREWALL — gỡ bỏ toàn bộ lớp bảo vệ"
echo ""
echo "    ⚠ NHẮC NHỞ AN TOÀN:"
echo "    Trước khi tiếp tục, hãy đảm bảo máy Victim đã bật:"
echo "       sudo sysctl -w net.ipv4.tcp_syncookies=1"
echo "    Nếu chưa làm, Ctrl+C ngay bây giờ, SSH vào Victim và thực hiện."
echo ""
read -p "[?] Đã xác nhận Victim có tcp_syncookies=1? (y/N): " -r confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "[!] Hủy. Hãy cấu hình Victim trước."
    exit 1
fi

# ─────────────────────────────────────────
# Gỡ XDP nếu đang attach
# ─────────────────────────────────────────
echo "[*] Gỡ XDP khỏi $IFACE_IN nếu đang attach..."
ip link set dev "$IFACE_IN" xdp off 2>/dev/null \
    && echo "    [!] Đã gỡ XDP." \
    || echo "    [+] XDP không attach, bỏ qua."

# ─────────────────────────────────────────
# Flush toàn bộ iptables
# ─────────────────────────────────────────
echo "[*] Flush toàn bộ iptables rules..."
iptables -F
iptables -X
iptables -t mangle -F; iptables -t mangle -X
iptables -t nat    -F; iptables -t nat    -X

# ACCEPT mọi thứ — không có rule nào chặn bất cứ packet nào
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# Giữ lại duy nhất SSH để không mất session quản trị
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ─────────────────────────────────────────
# Sysctl — ip_forward bật, syncookies tắt trên Firewall
# (Firewall không cần syncookies vì nó chỉ forward, không terminate TCP)
# ─────────────────────────────────────────
echo "[*] Cấu hình sysctl..."
sysctl -w net.ipv4.ip_forward=1     >/dev/null
sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null  # Giống các kịch bản khác — Firewall không xử lý TCP

echo ""
echo "[+] Setup no-firewall hoàn tất!"
echo ""
echo "    Tóm tắt:"
echo "    - XDP  : không attach"
echo "    - iptables: chỉ còn ACCEPT all + SSH"
echo "    - Conntrack: sẽ ~0 (không có rule stateful nào)"
echo "    - Mọi packet từ Attacker sẽ đến thẳng Victim"
echo ""
echo "    Tiếp theo: sudo bash run_benchmark_no_firewall.sh"
