#!/usr/bin/env bash
# =============================================================================
# setup_iptables_only.sh  (revised for fair benchmark)
# =============================================================================
# Cấu hình tường lửa CHỈ dùng iptables (KHÔNG có XDP) cho kịch bản benchmark
# đối chứng với mô hình hybrid XDP + iptables.
#
# Kịch bản lab:
#   Attacker (.10, .50, .100 qua netns) ── Firewall ── Victim (nginx)
#
#   Phase 0 : Ổn định, đo baseline
#   Phase 1 : ICMP flood từ .100  (stateless, xuyên suốt)
#   Phase 2 : .10 truy cập web bình thường (1 req/s)
#   Phase 3 : SYN flood từ .50   (stateful, xuyên suốt)
#   Phase 4 : Giữ nguyên
#   Phase 5 : Dừng tấn công, đợi ổn định
#
# Luồng packet (iptables-only):
#   Internet → [NIC driver] → [kernel TCP/IP stack] → [iptables FORWARD] → Victim
#   (Không có XDP DROP sớm ở driver level — đây chính là điểm cần đo)
#
# Các thay đổi so với phiên bản trước (lý do ghi trong comment inline):
#   1. Đã bỏ JUNK_RULES, đưa ICMP DROP lên đầu FORWARD chain.
#   2. Bỏ tcp_syncookies=0 (confounding factor so với hybrid)
#   3. Bỏ nf_conntrack_max override (hybrid không set, giữ đồng nhất)
#   4. Gộp hai lần flush iptables thành một
#   5. Giữ 10.10.1.100 NGOÀI whitelist (đúng với vai trò attacker Phase 1)
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

# Whitelist: CHỈ gồm các IP client hợp lệ — KHÔNG có .100 (attacker ICMP flood).
# Trong hybrid, .100 bị XDP DROP trước khi chạm iptables nên dù hybrid có .100
# trong whitelist cũng vô hại. Ở đây không có XDP nên .100 bị chặn trực tiếp ở iptables.
WHITELIST_IPS=(
    "10.10.1.10"    # netns ns10 — client hợp lệ
    "10.10.1.11"    # netns ns11 — client hợp lệ
    "10.10.1.50"    # netns ns50 — whitelist nhưng sẽ tấn công SYN flood ở Phase 3
)

# IP attacker ICMP flood (Phase 1).
# Trong hybrid: bị XDP DROP ở driver level.
# Ở đây: đi vào kernel stack đầy đủ, bị chặn ở FORWARD chain.
ICMP_FLOOD_IP="10.10.1.100"

# Ngưỡng phát hiện SYN flood — giữ nguyên như hybrid để so sánh công bằng
SYN_RATE_LIMIT="20/second"
SYN_BURST=30

BLACKLIST_SET="ipt_only_blacklist"  # Tên khác để tránh conflict nếu chạy cùng máy
WHITELIST_SET="ipt_only_whitelist"

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
ip link set dev "$IFACE_IN" xdp off 2>/dev/null \
    && echo "    [!] Đã gỡ XDP khỏi $IFACE_IN" \
    || echo "    [+] XDP không attach trên $IFACE_IN, tiếp tục."

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
# Sysctl
# ─────────────────────────────────────────
echo "[*] Cấu hình sysctl..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# FIX 1: KHÔNG tắt tcp_syncookies.
# Phiên bản trước đặt tcp_syncookies=0, nhưng hybrid không làm vậy.
# Syncookies ảnh hưởng trực tiếp đến cách kernel xử lý SYN queue trong Phase 3:
# nếu bật, kernel không cần allocate conntrack entry đầy đủ cho mỗi SYN, giảm tải
# conntrack đáng kể; nếu tắt, conntrack phải xử lý mọi SYN thật → CPU và RAM cao hơn.
# Đây là confounding factor — giữ giá trị mặc định của kernel (thường là 1) ở cả hai setup.

# FIX 2: KHÔNG override nf_conntrack_max.
# Phiên bản trước đặt nf_conntrack_max=1048576 nhưng hybrid không làm.
# Nếu giá trị mặc định của kernel nhỏ hơn (~65536 trên VM nhỏ), iptables-only sẽ có
# lợi thế giả tạo khi SYN flood Phase 3 tràn bảng conntrack.
# → Để cả hai kịch bản chịu cùng giới hạn conntrack của kernel.

# ─────────────────────────────────────────
# Flush toàn bộ rules cũ + khởi tạo ipset (gộp làm một lần)
# ─────────────────────────────────────────
# FIX 3: Chỉ flush một lần. Phiên bản trước gọi iptables -F/-X hai lần
# (một lần trước khi tạo ipset, một lần sau) — không gây bug nhưng dễ gây nhầm lẫn.
echo "[*] Flush rules cũ và khởi tạo ipset..."
iptables -F
iptables -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat -F
iptables -t nat -X

iptables -P INPUT  ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# ─────────────────────────────────────────
# Cài đặt ipset nếu chưa có
# ─────────────────────────────────────────
if ! command -v ipset &>/dev/null; then
    echo "[*] Cài ipset..."
    apt-get install -y ipset >/dev/null
fi

ipset destroy "$BLACKLIST_SET" 2>/dev/null || true
ipset destroy "$WHITELIST_SET" 2>/dev/null || true

ipset create "$BLACKLIST_SET" hash:ip maxelem 65536
ipset create "$WHITELIST_SET" hash:ip maxelem 65536

for ip in "${WHITELIST_IPS[@]}"; do
    ipset add "$WHITELIST_SET" "$ip"
    echo "    + Whitelist: $ip"
done

# ─────────────────────────────────────────
# Tạo các chain tùy chỉnh
# ─────────────────────────────────────────
echo "[*] Tạo chains..."

# Chain BLACKLIST_CHECK — giống hybrid, kiểm tra ipset blacklist động.
# IP bị phát hiện tấn công SYN flood sẽ được đưa vào đây sau Phase 3.
iptables -N BLACKLIST_CHECK
iptables -A BLACKLIST_CHECK \
    -m set --match-set "$BLACKLIST_SET" src \
    -j LOG --log-prefix "${LOG_PREFIX}BLACKLIST-HIT " --log-level 4
iptables -A BLACKLIST_CHECK \
    -m set --match-set "$BLACKLIST_SET" src \
    -j DROP

# Chain STATEFUL_DETECT — phát hiện SYN flood từ whitelist (Phase 3).
# Logic giống hệt hybrid: hashlimit dưới ngưỡng → RETURN (cho qua),
# vượt ngưỡng → log + ghi vào recent table + DROP.
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
    -j LOG --log-prefix "${LOG_PREFIX}SYN-FLOOD-DETECTED " --log-level 4
iptables -A STATEFUL_DETECT -p tcp --syn \
    -m recent --name "ipt_only_syn" --set --rsource
iptables -A STATEFUL_DETECT -p tcp --syn \
    -j DROP

# Chain AUTO_BLACKLIST — tự động chặn IP đã tấn công SYN flood.
# Logic giống hybrid: nếu IP đã ghi vào recent table và vượt hitcount → DROP.
iptables -N AUTO_BLACKLIST
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "ipt_only_syn" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j LOG --log-prefix "${LOG_PREFIX}AUTO-BLACKLIST " --log-level 4
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "ipt_only_syn" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j DROP


# ─────────────────────────────────────────
# Cấu hình FORWARD chain chính
# ─────────────────────────────────────────
echo "[*] Cấu hình FORWARD chain..."

# Luôn cho phép loopback và SSH
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i "$IFACE_IN" -p tcp --dport 22 -j ACCEPT

# BƯỚC 0: DROP ICMP flood từ .100 (Phase 1)
# Đặt ở đầu chain, trước cả ESTABLISHED/RELATED.
iptables -A FORWARD -i "$IFACE_IN" -s "$ICMP_FLOOD_IP" -p icmp -j DROP

# Bước 1: ESTABLISHED/RELATED bypass toàn bộ chain phía dưới
iptables -A FORWARD -i "$IFACE_IN" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT

# Bước 2: Dynamic blacklist (IP bị phát hiện tấn công SYN flood sẽ vào đây)
iptables -A FORWARD -i "$IFACE_IN" -j BLACKLIST_CHECK

# Bước 3: Phát hiện SYN flood từ whitelist (Phase 3).
iptables -A FORWARD -i "$IFACE_IN" \
    -m set --match-set "$WHITELIST_SET" src \
    -p tcp --syn \
    -j STATEFUL_DETECT

# Bước 4: Auto-blacklist threshold check
iptables -A FORWARD -i "$IFACE_IN" -j AUTO_BLACKLIST

# Bước 5: Cho phép HTTP/HTTPS từ whitelist (mô phỏng service cần bảo vệ)
iptables -A FORWARD -i "$IFACE_IN" \
    -p tcp -m multiport --dports 80,443,8080 \
    -m conntrack --ctstate NEW \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# Bước 6: Cho phép ICMP từ whitelist (để test connectivity từ .10, .11)
iptables -A FORWARD -i "$IFACE_IN" \
    -p icmp --icmp-type echo-request \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# Bước 7: Log + DROP tất cả còn lại
iptables -A FORWARD -i "$IFACE_IN" \
    -j LOG --log-prefix "${LOG_PREFIX}DROP-DEFAULT " --log-level 4
iptables -A FORWARD -i "$IFACE_IN" -j DROP

# Cho phép reply traffic từ Victim đi ngược lại
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
echo "    - Chế độ         : iptables-only (KHÔNG có XDP)"
echo "    - Rule thật ICMP : DROP trực tiếp ICMP từ $ICMP_FLOOD_IP (Đầu chain FORWARD)"
echo "    - Blacklist set  : $BLACKLIST_SET (dynamic, ban đầu rỗng)"
echo "    - Whitelist set  : $WHITELIST_SET (${#WHITELIST_IPS[@]} IPs: ${WHITELIST_IPS[*]})"
echo "    - SYN threshold  : $SYN_RATE_LIMIT (burst: $SYN_BURST)"
echo ""
echo "    Các điều kiện đã đồng nhất với hybrid:"
echo "    - tcp_syncookies : KHÔNG override (dùng mặc định kernel)"
echo "    - conntrack_max  : KHÔNG override (dùng mặc định kernel)"
echo "    - ESTABLISHED/RELATED bypass phần lớn rule (nhưng sau ICMP DROP)"
echo "    - 10.10.1.100 NGOÀI whitelist (đúng vai trò attacker Phase 1)"
echo ""
echo "    Điểm khác biệt cốt lõi so với hybrid (đây là điều benchmark đo được):"
echo "    - ICMP flood (.100) đi vào kernel stack đầy đủ trước khi bị DROP ở iptables FORWARD"
echo "    - Conntrack phải tiếp nhận mọi NEW packet trước khi chặn hoặc chuyển tiếp"
echo ""
echo "    Tiếp theo: sudo bash run_benchmark_iptables_only.sh"