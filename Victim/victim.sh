#!/usr/bin/env bash
# =============================================================================
# victim.sh (Optimized for Benchmark)
# =============================================================================
# Cài đặt & cấu hình Nginx làm máy đích (Victim) cho benchmark.
# Chạy trên máy Victim (Ubuntu/Debian).
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────
# Bắt tham số truyền vào
# ─────────────────────────────────────────
FORCE=0
if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[!] Cần chạy với quyền root (sudo)"
    exit 1
fi

# ─────────────────────────────────────────
# KIỂM TRA NGINX ĐÃ CÀI CHƯA
# ─────────────────────────────────────────
if command -v nginx >/dev/null 2>&1; then
    if [[ $FORCE -eq 0 ]]; then
        echo "[+] Nginx đã được cài đặt sẵn trên hệ thống."
        echo "[i] Script tạm dừng để tránh ghi đè cấu hình hiện tại."
        echo "    Để áp dụng cấu hình benchmark và ghi đè, hãy chạy lệnh:"
        echo "    sudo bash victim.sh --force"
        exit 0
    else
        echo "[!] Chế độ --force được bật. Tiến hành sao lưu và ghi đè cấu hình Nginx..."
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak_$(date +%s) 2>/dev/null || true
    fi
else
    echo "[*] Nginx chưa được cài đặt. Tiến hành cài đặt..."
    sudo apt update -qq
    sudo apt install -y -qq nginx curl > /dev/null
fi

echo "[*] Cập nhật cấu hình Nginx tối ưu cho benchmark..."
# Ghi đè file cấu hình nginx
# Tăng giới hạn file descriptor cho worker để tương xứng với số connections
# Tắt keepalive để ép iptables phải xử lý nhiều trạng thái NEW và ESTABLISHED hơn
 # Tắt log để tránh Disk I/O can thiệp vào kết quả đo benchmark
cat > /etc/nginx/nginx.conf << 'NGINX_CONF'
user www-data;
worker_processes auto;

worker_rlimit_nofile 10000;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 0; 
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log off;
    error_log /var/log/nginx/error.log warn;

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
        index index.html index.htm;
        location / {
            try_files $uri $uri/ =404;
        }
    }
}
NGINX_CONF

# Ép nội dung index để đảm bảo response nhẹ nhất có thể
echo "<h1>Victim Server - Benchmark Target</h1>" > /var/www/html/index.html

echo "[*] Khởi động lại dịch vụ..."
systemctl enable nginx > /dev/null 2>&1
systemctl restart nginx

# ─────────────────────────────────────────
# Kiểm tra trạng thái
# ─────────────────────────────────────────
sleep 1
if curl -s -o /dev/null -w "%{http_code}" http://localhost/ | grep -q "200"; then
    echo "[+] THÀNH CÔNG: Nginx đã khởi động và sẵn sàng trên port 80."
    echo "    Truy cập test từ máy Firewall: curl http://10.10.2.2/"
else
    echo "[-] LỖI: Nginx không phản hồi HTTP 200. Kiểm tra bằng: sudo journalctl -u nginx"
    exit 1
fi