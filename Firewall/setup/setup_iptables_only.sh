#!/usr/bin/env bash
# =============================================================================
# setup_iptables_only.sh
# =============================================================================
# Cấu hình tường lửa CHỈ dùng iptables (KHÔNG có XDP) cho kịch bản benchmark
# đối chứng với mô hình hybrid XDP + iptables.
#
# Mục đích: So sánh "tốt hơn so với cái gì?"
#   → Kịch bản này loại bỏ hoàn toàn XDP để mọi packet — kể cả flood —
#     đều phải đi qua kernel network stack và bị iptables xử lý.
#
# Luồng xử lý packet (iptables-only):
#    Internet → [NIC driver] → [kernel TCP/IP stack] → [iptables FORWARD] → Victim
#              (Không có XDP DROP sớm ở driver level)
#
# Để đảm bảo công bằng với kịch bản hybrid, script này tái tạo:
#   1. Tương đương 1000 rule của XDP:
#      - 999 rule DROP rác cho dải 172.16.0.0/12 (giả lập lookup overhead)
#      - 1 rule DROP ICMP flood từ 10.10.1.100
#      → Toàn bộ nằm trong iptables chain thay vì XDP BPF map
#   2. Whitelist-based access control (ipset hash:ip)
#   3. SYN flood detection bằng hashlimit + recent module
#   4. Dynamic blacklist bằng ipset (không có XDP feedback, chỉ iptables)
#
# Điểm khác biệt cốt lõi so với hybrid:
#   - Không có tầng XDP DROP ở driver level (bỏ qua trước interrupt)
#   - 1000 rule nằm trong iptables → duyệt tuyến tính O(n) thay vì BPF LPM Trie O(log n)
#   - ICMP flood phải leo hết kernel stack mới bị drop → CPU và IRQ cao hơn nhiều
#   - Conntrack phải xử lý nhiều packet hơn trước khi DROP
#
# Yêu cầu: iptables, ipset, kernel modules nf_conntrack, xt_hashlimit, xt_recent
# Chạy với quyền root: sudo bash setup_iptables_only.sh
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────
# Cấu hình — giữ giống hệt hybrid để so sánh công bằng
# ─────────────────────────────────────────
IFACE_IN="${IFACE_IN:-enp0s8}"     # Interface nhìn về Attacker (giống hybrid)
IFACE_OUT="${IFACE_OUT:-enp0s9}"   # Interface nhìn về Victim   (giống hybrid)

# Giữ nguyên danh sách whitelist như hybrid
WHITELIST_IPS=(
    "10.10.1.10"    # netns ns10 — client hợp lệ
    "10.10.1.11"    # netns ns11 — client hợp lệ
    "10.10.1.50"    # netns ns50 — whitelist nhưng sẽ tấn công SYN flood ở Phase 3
)

# IP attacker ICMP flood (Phase 1) — trong hybrid bị XDP DROP, ở đây bị iptables DROP
ICMP_FLOOD_IP="10.10.1.100"

# Ngưỡng phát hiện SYN flood — giữ nguyên như hybrid để so sánh công bằng
SYN_RATE_LIMIT="20/second"
SYN_BURST=30

BLACKLIST_SET="ipt_only_blacklist"  # Tên khác để tránh conflict nếu chạy cùng máy
WHITELIST_SET="ipt_only_whitelist"

# Số rule rác cần nạp vào iptables (tương đương 999 junk rule của XDP)
JUNK_RULE_COUNT=999

# Dải IP rác — giống generate_xdp_rules.py, dùng 172.16.0.0/12
JUNK_BASE="172.16"

LOG_PREFIX="[IPT-ONLY] "  # Prefix khác với hybrid để phân biệt trong dmesg/syslog

# ─────────────────────────────────────────
# Kiểm tra quyền root
# ─────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root (sudo)"
    exit 1
fi

# ─────────────────────────────────────────
# Đảm bảo XDP đã bị tắt (nếu đang chạy)
# ─────────────────────────────────────────
echo "[*] Kiểm tra và gỡ XDP nếu đang attach trên $IFACE_IN..."
# Thử detach XDP bằng ip link — nếu không có XDP thì lệnh này vô hại
ip link set dev "$IFACE_IN" xdp off 2>/dev/null && echo "    [!] Đã gỡ XDP khỏi $IFACE_IN" || echo "    [+] XDP không attach trên $IFACE_IN, tiếp tục."

# ─────────────────────────────────────────
# Load kernel modules cần thiết
# ─────────────────────────────────────────
echo "[*] Load kernel modules..."
modprobe nf_conntrack        2>/dev/null || true
modprobe nf_conntrack_ipv4   2>/dev/null || true
modprobe xt_conntrack        2>/dev/null || true
modprobe xt_hashlimit        2>/dev/null || true
modprobe xt_recent           2>/dev/null || true
modprobe xt_set              2>/dev/null || true

# ─────────────────────────────────────────
# Sysctl — giữ giống hệt setup.sh của Attacker để công bằng
# ─────────────────────────────────────────
echo "[*] Cấu hình sysctl..."
sysctl -w net.ipv4.ip_forward=1                      >/dev/null
sysctl -w net.ipv4.tcp_syncookies=0                  >/dev/null  # Tắt để conntrack phải xử lý SYN thật
sysctl -w net.netfilter.nf_conntrack_max=1048576      >/dev/null  # Giống hybrid, tránh confounding factor

# ─────────────────────────────────────────
# Cài đặt ipset nếu chưa có
# ─────────────────────────────────────────
if ! command -v ipset &>/dev/null; then
    echo "[*] Cài ipset..."
    apt-get install -y ipset >/dev/null
fi

# ─────────────────────────────────────────
# Khởi tạo ipset (reset để bắt đầu sạch)
# ─────────────────────────────────────────
echo "[*] Khởi tạo ipset..."
ipset destroy "$BLACKLIST_SET" 2>/dev/null || true
ipset destroy "$WHITELIST_SET" 2>/dev/null || true

ipset create "$BLACKLIST_SET" hash:ip maxelem 65536
ipset create "$WHITELIST_SET" hash:ip maxelem 65536

for ip in "${WHITELIST_IPS[@]}"; do
    ipset add "$WHITELIST_SET" "$ip"
    echo "    + Whitelist: $ip"
done

# ─────────────────────────────────────────
# Flush toàn bộ rules cũ
# ─────────────────────────────────────────
echo "[*] Flush rules cũ..."
iptables -F
iptables -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat -F
iptables -t nat -X

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# ─────────────────────────────────────────
# Tạo các chain tùy chỉnh
# ─────────────────────────────────────────
echo "[*] Tạo chains..."

# Chain BLACKLIST_CHECK — giống hybrid, kiểm tra ipset blacklist động
iptables -N BLACKLIST_CHECK
iptables -A BLACKLIST_CHECK -m set --match-set "$BLACKLIST_SET" src \
    -j LOG --log-prefix "${LOG_PREFIX}BLACKLIST-HIT " --log-level 4
iptables -A BLACKLIST_CHECK -m set --match-set "$BLACKLIST_SET" src \
    -j DROP

# Chain STATEFUL_DETECT — giống hybrid, phát hiện SYN flood từ whitelist
iptables -N STATEFUL_DETECT
iptables -A STATEFUL_DETECT -p tcp --syn \
    -m hashlimit \
    --hashlimit-name "ipt_only_syn_detect" \
    --hashlimit-upto "$SYN_RATE_LIMIT" \
    --hashlimit-burst "$SYN_BURST" \
    --hashlimit-mode srcip \
    --hashlimit-htable-expire 10000 \
    -j RETURN
iptables -A STATEFUL_DETECT -p tcp --syn \
    -j LOG --log-prefix "${LOG_PREFIX}SYN-FLOOD-DETECTED" --log-level 4
iptables -A STATEFUL_DETECT -p tcp --syn \
    -m recent --name "ipt_only_syn" --set --rsource
iptables -A STATEFUL_DETECT -p tcp --syn \
    -j DROP

# Chain AUTO_BLACKLIST — giống hybrid
iptables -N AUTO_BLACKLIST
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "ipt_only_syn" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j LOG --log-prefix "${LOG_PREFIX}AUTO-BLACKLIST " --log-level 4
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "ipt_only_syn" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j DROP

# Chain JUNK_RULES — tương đương 999 XDP junk rule
# Mục đích: Buộc iptables phải duyệt qua một lượng rule tương đương XDP map
# Đây là điều tạo ra overhead O(n) mà trong hybrid XDP xử lý bằng BPF LPM Trie O(log n)
iptables -N JUNK_RULES

# ─────────────────────────────────────────
# Nạp 999 rule rác vào chain JUNK_RULES
# ─────────────────────────────────────────
echo "[*] Nạp $JUNK_RULE_COUNT rule rác vào JUNK_RULES chain..."
echo "    (Tương đương 999 junk entry trong XDP BPF map của hybrid)"

count=0
# Duyệt dải 172.16.x.0/24 → 172.31.x.0/24, mỗi subnet /24 là 1 rule
for second_octet in $(seq 16 31); do
    for third_octet in $(seq 0 255); do
        if [[ $count -ge $JUNK_RULE_COUNT ]]; then
            break 2
        fi
        subnet="${JUNK_BASE}.${second_octet}.${third_octet}.0/24"
        iptables -A JUNK_RULES -s "$subnet" -j DROP
        (( count++ ))
        # In tiến trình mỗi 100 rule
        if (( count % 100 == 0 )); then
            echo "    → Đã nạp $count/$JUNK_RULE_COUNT rule..."
        fi
    done
done

echo "    [+] Đã nạp $count rule rác."

# Rule thật cuối chain JUNK_RULES: DROP ICMP flood từ attacker ns100
# → Tương đương rule thật cuối cùng trong XDP map của hybrid
# → Trong hybrid: packet bị XDP DROP ở driver level, KHÔNG vào kernel stack
# → Ở đây: packet đi qua toàn bộ kernel stack, duyệt qua JUNK_RULES, mới bị DROP
iptables -A JUNK_RULES -s "$ICMP_FLOOD_IP" -p icmp -j DROP

echo "    [+] Rule thật: DROP ICMP từ $ICMP_FLOOD_IP (rule thứ $((count + 1)))"

# ─────────────────────────────────────────
# Cấu hình FORWARD chain chính
# ─────────────────────────────────────────
echo "[*] Cấu hình FORWARD chain..."

# Luôn cho phép loopback và SSH
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i "$IFACE_IN" -p tcp --dport 22 -j ACCEPT

# 1. JUNK_RULES trước tiên (giả lập overhead 1000 rule — điểm khác biệt chính so với XDP)
#    Trong hybrid: bước này thực hiện ở XDP (BPF map, O(log n))
#    Ở đây: iptables duyệt tuyến tính O(n) qua 1000 rule
iptables -A FORWARD -i "$IFACE_IN" -j JUNK_RULES

# 2. Dynamic blacklist (IP bị phát hiện tấn công sẽ vào đây)
iptables -A FORWARD -i "$IFACE_IN" -j BLACKLIST_CHECK

# 3. ESTABLISHED/RELATED — khả năng stateful của iptables
iptables -A FORWARD -i "$IFACE_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 4. Phát hiện SYN flood từ whitelist (Phase 3)
iptables -A FORWARD -i "$IFACE_IN" -m set --match-set "$WHITELIST_SET" src \
    -p tcp --syn \
    -j STATEFUL_DETECT

# 5. Auto-blacklist threshold check
iptables -A FORWARD -i "$IFACE_IN" -j AUTO_BLACKLIST

# 6. Cho phép HTTP/HTTPS từ whitelist
iptables -A FORWARD -i "$IFACE_IN" -p tcp -m multiport --dports 80,443,8080 \
    -m conntrack --ctstate NEW \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# 7. Cho phép ICMP từ whitelist
iptables -A FORWARD -i "$IFACE_IN" -p icmp --icmp-type echo-request \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# 8. Log + DROP tất cả còn lại
iptables -A FORWARD -i "$IFACE_IN" \
    -j LOG --log-prefix "${LOG_PREFIX}DROP-DEFAULT " --log-level 4
iptables -A FORWARD -i "$IFACE_IN" -j DROP

# 9. Cho phép reply từ Victim đi ngược lại
iptables -A FORWARD -i "$IFACE_OUT" -j ACCEPT

# ─────────────────────────────────────────
# Lưu rules để tham khảo và debug
# ─────────────────────────────────────────
echo "[*] Lưu rules vào /tmp/iptables_only_rules.txt..."
iptables-save > /tmp/iptables_only_rules.txt
ipset save    > /tmp/iptables_only_ipset.txt

echo ""
echo "[+] Cấu hình iptables-only hoàn tất!"
echo ""
echo "    Tóm tắt:"
echo "    - Chế độ: iptables-only (KHÔNG có XDP)"
echo "    - Junk rules: $count (duyệt tuyến tính O(n), trong JUNK_RULES chain)"
echo "    - Rule thật ICMP DROP: $ICMP_FLOOD_IP (cuối JUNK_RULES)"
echo "    - Blacklist set : $BLACKLIST_SET (dynamic, ban đầu rỗng)"
echo "    - Whitelist set : $WHITELIST_SET (${#WHITELIST_IPS[@]} IPs)"
echo "    - SYN threshold : $SYN_RATE_LIMIT (burst: $SYN_BURST)"
echo ""
echo "    [!] KHÁC BIỆT chính so với hybrid:"
echo "    - ICMP flood đi vào kernel stack đầy đủ trước khi bị DROP"
echo "    - 1000 rules duyệt O(n) thay vì BPF LPM Trie O(log n)"
echo "    - Conntrack phải tiếp nhận mọi packet trước khi JUNK_RULES drop"
echo ""
echo "    Tiếp theo: sudo bash run_benchmark_iptables_only.sh"
