# Benchmark hệ thống Firewall: XDP, Iptables và Hybrid

## 1. Tổng quan

Tài liệu mô tả quy trình benchmark hiệu năng firewall với 4 kịch bản:

* Hybrid (XDP + Iptables)
* Iptables Only
* XDP Only
* No Firewall

Mục tiêu: đánh giá hiệu năng xử lý packet, mức tiêu thụ tài nguyên và khả năng chống DDoS.

---

# 2. Kịch bản Hybrid (XDP + Iptables)

## 2.1. Chuẩn bị môi trường

### 2.1.1. Victim (Web Server)

* Triển khai Nginx phục vụ HTTP trên port 80
* Trả về response nhẹ (HTTP 200)

```bash
sudo bash victim.sh
```

---

### 2.1.2. Attacker

Sử dụng Network Namespace:

* ns10, ns11: client hợp lệ
* ns50: SYN flood (whitelist)
* ns100: ICMP flood

```bash
sudo bash Attacker/setup.sh
```

---

### 2.1.3. Firewall (Hybrid)

#### a. Iptables

* ipset whitelist / blacklist
* Giới hạn SYN Flood (~20 pkt/s)
* Auto blacklist

```bash
bash setup_iptables_hybird.sh
```

---

#### b. XDP Rules

* 999 rule rác
* 1 rule DROP ICMP

```bash
python3 generate_xdp_rules.py
```

---

#### c. Feedback Daemon

```bash
bash xdp_feedback_daemon.sh &
```

---

## 2.2. Benchmark

```bash
sudo bash run_benchmark_hybird.sh
```

### Phase

* Phase 0: Baseline
* Phase 1: ICMP Flood (XDP DROP)
* Phase 2: Flood + traffic hợp lệ
* Phase 3: SYN Flood từ whitelist
* Phase 4: Sau blacklist
* Phase 5: Cool-down

---

## 2.3. Phân tích

Dữ liệu:

/tmp/benchmark_results/

Vẽ biểu đồ:

```bash
python3 analyze_benchmark.py <metrics.csv> <events.csv>
```

---

# 3. Kịch bản Iptables Only

## 3.1. Cấu hình

```bash
bash setup_iptables_only.sh
```

### Đặc điểm

* Không có XDP
* 999 rule rác (JUNK_RULES)
* Lookup tuyến tính O(n)

---

## 3.2. Benchmark

```bash
sudo bash run_benchmark_iptables_only.sh
```

---

## 3.3. Nhận định

* CPU tăng mạnh
* IRQ cao
* Packet đi sâu vào kernel

---

# 4. Kịch bản XDP Only

## 4.1. Cấu hình

```bash
bash setup_xdp_only.sh
```

### Đặc điểm

* Xóa iptables
* Disable conntrack
* Chỉ dùng XDP

---

## 4.2. Benchmark

```bash
sudo bash run_benchmark_xdp_only.sh
```

---

## 4.3. Nhận định

Ưu điểm:

* CPU thấp
* IRQ thấp
* Drop tại NIC

Nhược điểm:

* Không có stateful
* Không chặn SYN flood từ whitelist

---

# 5. Kịch bản No Firewall

## 5.1. Mục tiêu

Đánh giá hệ thống khi không có firewall.

---

## 5.2. Cấu hình

```bash
bash setup_no_firewall.sh
```

### Đặc điểm

* Flush iptables
* Default ACCEPT
* Không có XDP
* Conntrack hoạt động

---

## 5.3. Benchmark

```bash
sudo bash run_benchmark_no_firewall.sh
```

---

## 5.4. Hành vi

* Phase 1: ICMP flood vào thẳng kernel
* Phase 2: Traffic hợp lệ bị ảnh hưởng
* Phase 3: SYN flood làm đầy conntrack
* Phase 4: Victim quá tải
* Phase 5: Hồi phục chậm

---

## 5.5. Kết quả dự kiến

* CPU cao nhất
* Conntrack bão hòa
* Throughput không ổn định
* Dễ bị DoS

---

# 6. So sánh

| Kịch bản      | Hiệu năng  | Bảo mật         | Nhận định                |
| ------------- | ---------- | --------------- | ------------------------ |
| No Firewall   | Rất thấp   | Không có        | Tệ nhất                  |
| Iptables Only | Trung bình | Tốt             | Tốn CPU                  |
| XDP Only      | Rất cao    | Kém (stateless) | Nhanh nhưng thiếu bảo vệ |
| Hybrid        | Tốt        | Tốt nhất        | Cân bằng                 |

---

# 7. Kết luận

* XDP: xử lý nhanh tại NIC
* Iptables: xử lý stateful
* Hybrid: tối ưu nhất
* No Firewall: baseline xấu nhất
