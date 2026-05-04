#!/usr/bin/env bash
# setup_ns_v3.sh - Tạo 4 Network Namespace cho lab DDoS (Đã fix lỗi IP & Route)
set -euo pipefail

# ================= CẤU HÌNH =================
OUT_IFACE="enp0s8"          # Interface vật lý nối tới Firewall
FW_IP="10.10.1.1"           # IP Firewall phía Attacker
VICTIM_NET="10.10.2.0/24"   # Mạng phía Victim
declare -A NS_LIST=(
    ["ns10"]="10.10.1.10"
    ["ns11"]="10.10.1.11"
    ["ns50"]="10.10.1.50"
    ["ns100"]="10.10.1.100"
)
TRANSIT_PREFIX="10.254.0"   # Dải IP transit nội bộ (valid /24)
IDX=10

# ================= DỌN DẸP =================
echo "[*] Đang dọn dẹp namespace/veth cũ..."
for ns in "${!NS_LIST[@]}"; do
    ip netns del $ns 2>/dev/null || true
    ip link del "veth_${ns}" 2>/dev/null || true
done

# ================= SYSCTL TOÀN CỤC =================
echo "[*] Điều chỉnh kernel cho lab DDoS..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.accept_local=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.proxy_arp=1 >/dev/null 2>&1 || true

# Conntrack (tùy chọn, chỉ áp dụng nếu kernel hỗ trợ)
modprobe nf_conntrack 2>/dev/null || true
if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
    sysctl -w net.netfilter.nf_conntrack_max=1048576 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1 || true
fi

# ================= ROUTE TRÊN HOST =================
echo "[*] Thiết lập route tới Victim..."
ip route add ${VICTIM_NET} via ${FW_IP} dev ${OUT_IFACE} 2>/dev/null || true

# ================= TẠO NAMESPACE & VETH =================
echo "[*] Đang tạo namespaces..."
for ns in "${!NS_LIST[@]}"; do
    ATTACK_IP="${NS_LIST[$ns]}"
    VETH_HOST="veth_${ns}"
    VETH_NS="veth_${ns}_in"
    
    # Sinh IP transit hợp lệ (4 octet), nhảy 2 đơn vị để tránh trùng subnet /30
    HOST_VETH_IP="${TRANSIT_PREFIX}.${IDX}"

    echo "[+] Thiết lập $ns (Attack IP: $ATTACK_IP)..."

    # 1. Tạo netns và veth pair
    ip netns add $ns
    ip link add $VETH_HOST type veth peer name $VETH_NS
    ip link set $VETH_NS netns $ns

    # 2. Cấu hình TRONG netns
    ip netns exec $ns ip addr add ${ATTACK_IP}/32 dev $VETH_NS
    ip netns exec $ns ip link set $VETH_NS up
    ip netns exec $ns ip link set lo up
    # Route default trỏ về host, thêm onlink để kernel không kiểm tra subnet gateway
    ip netns exec $ns ip route add default via ${HOST_VETH_IP} dev $VETH_NS onlink

    # 3. Cấu hình TRÊN HOST
    ip addr add ${HOST_VETH_IP}/30 dev $VETH_HOST
    ip link set $VETH_HOST up
    ip link set $VETH_HOST txqueuelen 10000
    # Route định hướng packet reply từ Victim vào đúng netns
    ip route add ${ATTACK_IP}/32 dev $VETH_HOST

    # 4. Sysctl riêng cho veth host
    sysctl -w net.ipv4.conf.${VETH_HOST}.proxy_arp=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.${VETH_HOST}.accept_local=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.${VETH_HOST}.rp_filter=0 >/dev/null 2>&1 || true

    echo "    ↳ $ns: ${ATTACK_IP} -> ${HOST_VETH_IP} -> ${OUT_IFACE}"
    IDX=$((IDX + 2))
done

echo ""
echo "[✅] HOÀN TẤT! Cấu hình lab DDoS đã sẵn sàng."
echo "[💡] Lệnh test nhanh:"
echo "    ip netns exec ns10 ping -c 3 10.10.2.2"
echo "    ip netns exec ns50 curl -s http://10.10.2.2 || echo 'Victim không phản hồi HTTP'"