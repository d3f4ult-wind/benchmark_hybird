#!/usr/bin/env bash
# =============================================================================
# setup_xdp_only.sh
# =============================================================================
# Cấu hình tường lửa CHỈ dùng XDP (KHÔNG có iptables stateful) cho kịch bản
# benchmark đối chứng — minh họa giới hạn của stateless-only firewall.
#
# Mục đích trong bộ so sánh:
#   no_firewall  → baseline tuyệt đối
#   iptables_only → netfilter truyền thống, O(n) rule lookup
#   [XDP-only]   → stateless nhanh, nhưng mù với TCP state  ← file này
#   hybrid       → XDP + iptables, tốt nhất cả hai
#
# Luồng xử lý packet (XDP-only):
#   Internet → [XDP: DROP/PASS dựa trên BPF map] → FORWARD thẳng tới Victim
#              (Không có conntrack, không có stateful detection)
#
# Điểm khác biệt cốt lõi so với hybrid:
#   - Không có iptables → không có conntrack → không theo dõi TCP state
#   - SYN flood từ whitelist IP (Phase 3) sẽ KHÔNG bị phát hiện và KHÔNG bị chặn
#     vì XDP chỉ match theo IP/port/proto tĩnh, không hiểu "flood" là gì
#   - Đây chính là "điểm mù" của stateless mà kịch bản này muốn minh họa
#
# Rule XDP được nạp giống hệt hybrid:
#   - 999 junk rules (172.16.0.0/12) để tạo lookup pressure lên BPF LPM Trie
#   - 1 rule thật: DROP ICMP từ 10.10.1.100 (ns100)
#   - PASS rules cho whitelist IPs (ns10, ns11, ns50)
#
# Yêu cầu:
#   - XDP binary (xdp-filter hoặc tương đương) đã được build và đang chạy
#   - generate_xdp_rules.py có sẵn trong cùng thư mục
#   - XDP REST API đang lắng nghe tại $XDP_API
#   - Chạy với quyền root
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────
# Cấu hình — giữ giống hybrid
# ─────────────────────────────────────────
IFACE_IN="${IFACE_IN:-enp0s8}"
XDP_API="${XDP_API:-http://localhost:8080}"

# ─────────────────────────────────────────
# Kiểm tra quyền root
# ─────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root (sudo)"
    exit 1
fi

echo "[*] Chế độ: XDP-only (KHÔNG có iptables stateful)"

# ─────────────────────────────────────────
# Sysctl — giữ giống hybrid để so sánh công bằng
# ─────────────────────────────────────────
echo "[*] Cấu hình sysctl..."
sysctl -w net.ipv4.ip_forward=1      >/dev/null
sysctl -w net.ipv4.tcp_syncookies=0  >/dev/null  # Giống hybrid — tắt để SYN flood không bị kernel tự xử lý

# ─────────────────────────────────────────
# Flush toàn bộ iptables — đảm bảo không còn rule nào can thiệp
# ─────────────────────────────────────────
echo "[*] Flush iptables (để XDP là lớp duy nhất)..."
iptables -F
iptables -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat -F
iptables -t nat -X

# ACCEPT tất cả — packet qua được XDP sẽ forward tự do, không bị iptables chặn
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# Cho phép SSH vào Firewall (bảo vệ session quản trị)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i "$IFACE_IN" -p tcp --dport 22 -j ACCEPT

# ─────────────────────────────────────────
# Không load nf_conntrack — XDP-only không dùng conntrack
# Giữ module ở trạng thái không active để đo conntrack=0 là thật,
# không phải vì conntrack đang đầy hay bị disable.
# ─────────────────────────────────────────
echo "[*] Kiểm tra trạng thái conntrack..."
if cat /proc/sys/net/netfilter/nf_conntrack_count >/dev/null 2>&1; then
    echo "    [i] nf_conntrack đang loaded — giá trị sẽ gần 0 vì không có iptables stateful rule."
    echo "    [i] Đây là hành vi đúng: XDP không dùng conntrack."
else
    echo "    [+] nf_conntrack không active — conntrack_count sẽ báo 0, ghi N/A vào CSV."
fi

# ─────────────────────────────────────────
# Kiểm tra XDP API còn sống không
# ─────────────────────────────────────────
echo "[*] Kiểm tra XDP REST API tại $XDP_API..."
if curl -s --max-time 3 "$XDP_API/health" >/dev/null 2>&1; then
    echo "    [+] XDP API đang hoạt động."
else
    echo "    [!] CẢNH BÁO: XDP API không phản hồi tại $XDP_API"
    echo "        Hãy khởi động XDP daemon trước, sau đó chạy lại script này."
    exit 1
fi

# ─────────────────────────────────────────
# Nạp rules vào XDP — giống hệt hybrid
# generate_xdp_rules.py tạo: 999 junk + PASS whitelist + 1 DROP ICMP attacker
# ─────────────────────────────────────────
echo "[*] Nạp 1000 XDP rules (giống hybrid)..."
echo "    → 999 junk rules (172.16.0.0/12)"
echo "    → PASS: 10.10.1.10, 10.10.1.11, 10.10.1.50 (whitelist)"
echo "    → DROP ICMP: 10.10.1.100 (ICMP flood attacker)"

python3 generate_xdp_rules.py --xdp-api "$XDP_API"

echo ""
echo "[+] Cấu hình XDP-only hoàn tất!"
echo ""
echo "    Tóm tắt:"
echo "    - Lớp bảo vệ: XDP BPF LPM Trie (stateless, O(log n))"
echo "    - KHÔNG có iptables stateful — không có conntrack"
echo "    - SYN flood từ whitelist IP sẽ KHÔNG bị phát hiện (điểm mù của stateless)"
echo "    - 1000 XDP rules giống hệt hybrid để overhead lookup tương đương"
echo ""
echo "    [!] Hành vi kỳ vọng ở Phase 3:"
echo "        SYN flood từ 10.10.1.50 (whitelist) sẽ lọt qua XDP và đổ thẳng vào Victim."
echo "        Đây KHÔNG phải lỗi — đây là giới hạn của stateless firewall."
echo ""
echo "    Tiếp theo: sudo bash run_benchmark_xdp_only.sh"
