#!/usr/bin/env bash
# =============================================================================
# setup_iptables.sh
# =============================================================================
# Cấu hình iptables cho kịch bản benchmark kết hợp XDP + iptables (Chạy trên máy Firewall):
#
# Luồng xử lý packet:
#    Internet → [XDP: DROP flood, PASS whitelist] → [iptables: stateful]
#
# Iptables đảm nhiệm:
#     1. Cho phép các kết nối đã được thiết lập (ESTABLISHED/RELATED)
#     2. Cho phép whitelist IP kết nối mới
#     3. Chặn IP trong dynamic blacklist (ipset)
#     4. Phát hiện SYN flood từ IP whitelist (tấn công stateful bất ngờ)
#     5. Tự động đưa IP tấn công vào blacklist → chặn sớm
#
# Yêu cầu: iptables, ipset, kernel modules ip_conntrack
# Chạy với quyền root: sudo bash setup_iptables.sh
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────
# Cấu hình — chỉnh theo lab của bạn
# ─────────────────────────────────────────
IFACE_IN="${IFACE_IN:-enp0s8}"                        # Interface nhìn về Attacker
IFACE_OUT="${IFACE_OUT:-enp0s9}"                      # Interface nhìn về Victim
WHITELIST_IPS=(                                # IP được phép đi qua XDP vào iptables
    "10.10.1.10"                                # netns ns10 client hợp lệ 1
    "10.10.1.11"                                # netns ns11 client hợp lệ 2
    "10.10.1.50"
    "10.10.1.100"                            # netns ns50 IP whitelist nhưng sẽ tấn công stateful
)
ATTACKER_STEALTH_IP="10.10.1.50"               # IP whitelist thực hiện tấn công stateful
SYN_RATE_LIMIT="20/second"                    # Ngưỡng SYN flood (packet/s) để trigger block
SYN_BURST=30                                   # Burst cho phép trước khi block
BLACKLIST_SET="xdp_iptables_blacklist"         # Tên ipset blacklist động
WHITELIST_SET="xdp_iptables_whitelist"         # Tên ipset whitelist

LOG_PREFIX="[FW-BENCH] " # Prefix cho log iptables để dễ phân biệt trong syslog

# ─────────────────────────────────────────
# Kiểm tra quyền root
# ─────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root (sudo)"
    exit 1
fi

echo "[*] Bật IP Forwarding cho $IFACE_IN và $IFACE_OUT..."
sysctl -w net.ipv4.ip_forward=1

echo "[*] Bắt đầu cấu hình iptables cho benchmark..."

# ─────────────────────────────────────────
# Cài đặt ipset nếu chưa có
# ─────────────────────────────────────────
if ! command -v ipset &>/dev/null; then
    echo "[*] Cài ipset..."
    apt-get install -y ipset >/dev/null
fi

# ─────────────────────────────────────────
# Tạo ipset (xóa nếu đã tồn tại để reset)
# ─────────────────────────────────────────
echo "[*] Khởi tạo ipset..."
# ipset không thể xóa vì iptables cũ đang dùng, nên xóa rules cũ trước, sau đó xóa ipset nếu tồn tại
iptables -F
iptables -X
ipset destroy "$BLACKLIST_SET" 2>/dev/null || true
ipset destroy "$WHITELIST_SET" 2>/dev/null || true

# hashsize=1024 phù hợp cho lab nhỏ; timeout=0 = không tự hết hạn
ipset create "$BLACKLIST_SET" hash:ip  maxelem 65536
ipset create "$WHITELIST_SET" hash:ip  maxelem 65536

# Thêm whitelist IPs
for ip in "${WHITELIST_IPS[@]}"; do
    ipset add "$WHITELIST_SET" "$ip"
    echo "    + Whitelist: $ip"
done

# ─────────────────────────────────────────
# Flush tất cả rules cũ và đặt policy mặc định
# ─────────────────────────────────────────
echo "[*] Flush rules cũ và đặt policy mặc định..."
iptables -F
iptables -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat    -F
iptables -t nat    -X

# Policy mặc định: ACCEPT (XDP đã làm lớp bảo vệ đầu tiên)
# Trong production thật nên là DROP, nhưng ở đây ta cần flexibility khi test
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# ─────────────────────────────────────────
# Tạo chain tùy chỉnh
# ─────────────────────────────────────────
echo "[*] Tạo chains..."

# Chain BLACKLIST: kiểm tra dynamic blacklist
iptables -N BLACKLIST_CHECK
iptables -A BLACKLIST_CHECK -m set --match-set "$BLACKLIST_SET" src \
    -j LOG --log-prefix "${LOG_PREFIX}BLACKLIST-HIT " --log-level 4
iptables -A BLACKLIST_CHECK -m set --match-set "$BLACKLIST_SET" src \
    -j DROP

# Chain STATEFUL_ATTACK_DETECT: phát hiện SYN flood từ whitelist
# Đây là điểm mấu chốt của kịch bản: whitelist IP vượt qua XDP nhưng
# bắt đầu tấn công stateful — iptables phát hiện và xử lý.
iptables -N STATEFUL_DETECT
iptables -A STATEFUL_DETECT -p tcp --syn \
    -m hashlimit \
    --hashlimit-name "syn_flood_detect" \
    --hashlimit-upto "$SYN_RATE_LIMIT" \
    --hashlimit-burst "$SYN_BURST" \
    --hashlimit-mode srcip \
    --hashlimit-htable-expire 10000 \
    -j RETURN   
# Dưới ngưỡng → cho qua
# Vượt ngưỡng → log + đưa vào blacklist + DROP
iptables -A STATEFUL_DETECT -p tcp --syn \
    -j LOG --log-prefix "${LOG_PREFIX}SYN-FLOOD-DETECTED " --log-level 4
iptables -A STATEFUL_DETECT -p tcp --syn \
    -m recent --name "syn_flood" --set --rsource
# Drop gói vượt ngưỡng
iptables -A STATEFUL_DETECT -p tcp --syn \
    -j DROP

# Chain tự động blacklist: khi IP bị phát hiện SYN flood,
# thêm vào ipset để chặn sớm ở tất cả các kết nối tiếp theo
iptables -N AUTO_BLACKLIST
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "syn_flood" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j LOG --log-prefix "${LOG_PREFIX}AUTO-BLACKLIST " --log-level 4
# Trigger script thêm IP vào ipset (xem auto_blacklist_daemon.sh)
iptables -A AUTO_BLACKLIST -p tcp --syn \
    -m recent --name "syn_flood" --rcheck --seconds 5 --hitcount 50 --rsource \
    -j DROP

# ─────────────────────────────────────────
# Rules chính trên FORWARD chain
# ─────────────────────────────────────────
echo "[*] Cấu hình FORWARD chain..."

# Luôn cho phép loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i "$IFACE_IN" -p tcp --dport 22 -j ACCEPT # Cho phép SSH vào Firewall

# 1. Kiểm tra blacklist TRƯỚC (IP đã bị blacklist → DROP ngay)
#    Đây là bước "iptables chặn sớm" sau khi auto-blacklist kích hoạt
iptables -A FORWARD -i "$IFACE_IN" -j BLACKLIST_CHECK

# 2. ESTABLISHED/RELATED: tim năng lực stateful của iptables
#    Đây là điều XDP stateless hoàn toàn không làm được
iptables -A FORWARD -i "$IFACE_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Kiểm tra SYN flood từ whitelist (tấn công stateful bất ngờ)
iptables -A FORWARD -i "$IFACE_IN" -m set --match-set "$WHITELIST_SET" src \
    -p tcp --syn \
    -j STATEFUL_DETECT

# 4. Kiểm tra auto-blacklist threshold
iptables -A FORWARD -i "$IFACE_IN" -j AUTO_BLACKLIST

# 5. Cho phép HTTP/HTTPS từ whitelist (mô phỏng service cần bảo vệ)
iptables -A FORWARD -i "$IFACE_IN" -p tcp -m multiport --dports 80,443,8080 \
    -m conntrack --ctstate NEW \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# 6. ICMP: cho phép ping từ whitelist (để test connectivity)
iptables -A FORWARD -i "$IFACE_IN" -p icmp --icmp-type echo-request \
    -m set --match-set "$WHITELIST_SET" src \
    -j ACCEPT

# 7. Log và DROP tất cả còn lại (không phải whitelist, không phải established)
iptables -A FORWARD -i "$IFACE_IN" \
    -j LOG --log-prefix "${LOG_PREFIX}DROP-DEFAULT " --log-level 4
iptables -A FORWARD -i "$IFACE_IN" -j DROP

# 8. Cho phép traffic reply từ Victim đi ngược lại
iptables -A FORWARD -i "$IFACE_OUT" -j ACCEPT

# ─────────────────────────────────────────
# Lưu rules để tham khảo
# ─────────────────────────────────────────
echo "[*] Lưu rules vào /tmp/iptables_rules_backup.txt..."
iptables-save > /tmp/iptables_rules_backup.txt
ipset save      > /tmp/ipset_backup.txt

# ─────────────────────────────────────────
# Bật conntrack (đảm bảo module được load)
# ─────────────────────────────────────────
echo "[*] Load kernel modules conntrack..."
modprobe nf_conntrack        2>/dev/null || true
modprobe nf_conntrack_ipv4   2>/dev/null || true
modprobe xt_conntrack        2>/dev/null || true
modprobe xt_hashlimit        2>/dev/null || true
modprobe xt_set              2>/dev/null || true

echo ""
echo "[+] Cấu hình iptables hoàn tất!"
echo ""
echo "    Tóm tắt:"
echo "    - Blacklist set: $BLACKLIST_SET (dynamic, ban đầu rỗng)"
echo "    - Whitelist set: $WHITELIST_SET (${#WHITELIST_IPS[@]} IPs)"
echo "    - SYN flood threshold: $SYN_RATE_LIMIT (burst: $SYN_BURST)"
echo "    - Tấn công stateful được theo dõi từ: $ATTACKER_STEALTH_IP"
echo ""

