#!/usr/bin/env python3
"""
generate_xdp_rules.py
---------------------
Tạo 1000 rules cho XDP firewall (Chạy trên máy firewall) để benchmark hiệu năng so với iptables.:
  - 999 rules "rác" (junk) trỏ đến các subnet không tồn tại trong lab,
    mục đích là buộc XDP phải duyệt qua tất cả trước khi khớp rule cuối.
  - Rule thứ 1000: DROP toàn bộ traffic từ dải IP của attacker (ICMP flood).

Lưu ý kỹ thuật:
  XDP trong dự án này dùng BPF LPM Trie (Longest Prefix Match), nên về lý thuyết
  lookup là O(log n) thay vì O(n). Tuy nhiên, việc nhồi 999 entry vào trie vẫn
  tạo ra overhead bộ nhớ và cache pressure khác nhau so với trie ít entry.
  Đây chính là điểm benchmark thú vị khi so với iptables (duyệt tuyến tính O(n)).

Cách dùng:
  python3 generate_xdp_rules.py --xdp-api http://localhost:8080
  hoặc chỉ in ra file:
  python3 generate_xdp_rules.py --dry-run --output rules_generated.txt
"""

import argparse
import ipaddress
import json
import sys
import time
import urllib.request
import urllib.error


# ─────────────────────────────────────────────
# Cấu hình dải IP
# ─────────────────────────────────────────────
# Dải IP "rác" — chọn từ 172.16.0.0/12 (private, không dùng trong lab) để tránh vô tình chặn máy thật.

JUNK_BASE_NETWORK = ipaddress.IPv4Network("172.16.0.0/12")

# IP của nens ns100 trên máy attacker (ICMP flood) — đây là rule "thật" cuối cùng
ATTACKER_FLOOD_SUBNET = "10.10.1.100/32" 

# Dải IP whitelist (được phép qua, không bị chặn)
WHITELIST_IPS = [
    "10.10.1.10/32",   # netns ns10 client hợp lệ 1
    "10.10.1.11/32",   # netns ns11 client hợp lệ 2
    "10.10.1.50/32",   # netns ns50 IP whilelist sẽ bị dùng tấn công SYN flood ở Phase 3
]
# Port 0 = áp dụng cho tất cả port; proto 0 = tất cả protocol
# Theo API của xdp-filter: proto=1 là ICMP, 6=TCP, 17=UDP, chưa có khái niệm "all protocol" nên dùng 0 để rule rác không bị bỏ qua khi lookup ICMP cuối cùng.
JUNK_PORT  = 0
JUNK_PROTO = 0   # all protocols cho rule rác (để giả lập rule thật)

BLOCK_PROTO = 1  # ICMP cho rule cuối
BLOCK_PORT  = 0  # ICMP không có port khái niệm


def generate_junk_subnets(count: int) -> list[str]:
    """
    Sinh 'count' subnet /24 khác nhau từ dải 172.16.0.0/12.
    172.16.0.0/12 chứa 172.16.x.x → 172.31.x.x = 16*256 = 4096 subnet /24,
    đủ chỗ cho 999 entry mà không trùng nhau.
    """
    subnets = []
    # Lấy tất cả /24 trong 172.16.0.0/12
    all_24 = list(JUNK_BASE_NETWORK.subnets(new_prefix=24))
    if count > len(all_24):
        raise ValueError(f"Không đủ subnet: yêu cầu {count}, chỉ có {len(all_24)}")
    for i in range(count):
        subnets.append(str(all_24[i]))
    return subnets


def build_rule_payload(subnet: str, port: int, proto: int, action: str) -> dict:
    """Tạo JSON body theo format REST API của xdp-filter."""
    return {
        "subnet": subnet,
        "port":   port,
        "proto":  proto,
        "action": action   # "DROP" hoặc "PASS"
    }


def post_rule(api_base: str, payload: dict, retries: int = 3) -> bool:
    """Gửi POST /rules lên XDP REST API. Trả về True nếu thành công."""
    url  = f"{api_base.rstrip('/')}/rules"
    data = json.dumps(payload).encode("utf-8")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 201
        except urllib.error.HTTPError as e:
            print(f"  [!] HTTP {e.code} cho {payload['subnet']} (lần {attempt}): {e.read().decode()}")
        except urllib.error.URLError as e:
            print(f"  [!] Kết nối thất bại (lần {attempt}): {e.reason}")
            time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser(description="Tạo 1000 XDP rules cho benchmark")
    parser.add_argument("--xdp-api",  default="http://localhost:8080",
                        help="Base URL của XDP REST API (default: http://localhost:8080)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Không gửi lên API, chỉ in ra màn hình / file")
    parser.add_argument("--output",   default="",
                        help="Nếu dry-run, ghi vào file này thay vì stdout")
    parser.add_argument("--junk-count", type=int, default=999,
                        help="Số lượng rule rác (default: 999)")
    parser.add_argument("--attacker-subnet", default=ATTACKER_FLOOD_SUBNET,
                        help=f"Subnet của attacker ICMP flood (default: {ATTACKER_FLOOD_SUBNET})")
    args = parser.parse_args()

    junk_subnets = generate_junk_subnets(args.junk_count)

    # Tổng hợp tất cả rules: junk trước, rule thật sau cùng
    all_rules = []
    for subnet in junk_subnets:
        all_rules.append(build_rule_payload(subnet, JUNK_PORT, JUNK_PROTO, "DROP"))
    # Rule PASS cho whitelist — phải nằm trước rule DROP attacker
    for wl_ip in WHITELIST_IPS:
        all_rules.append(build_rule_payload(wl_ip, 80, 6, "PASS"))
    # Rule 1003: chặn ICMP flood từ attacker
    all_rules.append(build_rule_payload(args.attacker_subnet, BLOCK_PORT, BLOCK_PROTO, "DROP"))

    print(f"[*] Tổng số rules sẽ nạp: {len(all_rules)}")
    print(f"    - {args.junk_count} rule rác (DROP, 172.16.x.x/24)")
    print(f"    - {len(WHITELIST_IPS)} rule PASS whitelist")
    print(f"    - 1 rule thật: DROP ICMP từ {args.attacker_subnet}")

    if args.dry_run:
        # Chỉ in ra, không gửi API
        lines = [json.dumps(r) for r in all_rules]
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(lines) + "\n")
            print(f"[*] Đã ghi {len(lines)} rules vào {args.output}")
        else:
            for line in lines:
                print(line)
        return

    # Gửi lên API
    success = 0
    fail    = 0
    start   = time.time()
    for i, rule in enumerate(all_rules, 1):
        label = "JUNK" if i <= args.junk_count else "REAL"
        ok = post_rule(args.xdp_api, rule)
        if ok:
            success += 1
        else:
            fail += 1
        # In tiến trình mỗi 100 rule
        if i % 100 == 0 or i == len(all_rules):
            elapsed = time.time() - start
            print(f"  [{label}] {i}/{len(all_rules)} rules — OK={success} FAIL={fail} ({elapsed:.1f}s)")

    print(f"\n[+] Hoàn tất: {success} thành công, {fail} thất bại trong {time.time()-start:.2f}s")
    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
