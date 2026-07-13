# Packet Sniffer (libpcap / AF_PACKET)

Module thu thập và phân tích gói tin ở tầng liên kết dữ liệu (Layer 2 — AF_PACKET) sử dụng ngôn ngữ C và thư viện `libpcap` phiên bản hiện đại trên Linux.

## Tính năng

- **Chọn card mạng tương tác**: Tự động liệt kê tất cả interface khả dụng kèm địa chỉ IP, trạng thái (UP/RUNNING/LOOPBACK) — không cần gõ `ip link` thủ công.
- **Kiến trúc Modern libpcap**: Chuỗi hàm `pcap_create()` → `pcap_set_immediate_mode()` → `pcap_set_promisc()` → `pcap_activate()` thay vì `pcap_open_live()` đã lỗi thời.
- **Phân tích gói tin nhiều tầng**:
  - **Layer 2 (Ethernet)**: MAC nguồn/đích, EtherType.
  - **Layer 3 (IPv4)**: IP nguồn/đích, Protocol. Bỏ qua IPv6 và fragment.
  - **Layer 4 (TCP/UDP)**: Port nguồn/đích.
  - **Payload**: In toàn bộ bytes dạng hex dump, 16 bytes mỗi dòng kèm offset.
- **Dừng an toàn**: Bắt tín hiệu `SIGINT` (Ctrl+C) để ngắt vòng lặp bằng `pcap_breakloop()` và hiển thị thống kê (`ps_recv`, `ps_drop`, `ps_ifdrop`).
- **An toàn bộ nhớ**: Kiểm tra biên (`caplen`) nghiêm ngặt trước mọi lần ép kiểu cấu trúc header để tránh buffer overflow.

## Cấu trúc mã nguồn

| Hàm | Vai trò |
|-----|---------|
| `select_interface()` | Liệt kê card mạng, cho phép chọn tương tác |
| `parse_ethernet()` | Phân tích Ethernet header (Layer 2) |
| `parse_ipv4()` | Phân tích IPv4 header (Layer 3) |
| `parse_tcp()` | Phân tích TCP header (Layer 4) |
| `parse_udp()` | Phân tích UDP header (Layer 4) |
| `packet_handler()` | Callback điều phối của `pcap_loop` |
| `on_sigint()` | Xử lý SIGINT để dừng an toàn |

## Cài đặt

Trên Ubuntu / Debian / Kali Linux:

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev
```

## Biên dịch

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic sniffer.c -o sniffer -lpcap
```

## Chạy chương trình

### Chế độ chọn card tương tác (không cần tham số)

```bash
sudo ./sniffer
```

Chương trình tự động hiển thị danh sách card mạng:

```
========================================
  Available Network Interfaces
========================================

  [1] lo
      Flags       : LOOPBACK UP RUNNING
      IPv4        : 127.0.0.1

  [2] eth0
      Flags       : UP RUNNING
      IPv4        : 192.168.1.146

  [3] wlan0
      Flags       : UP RUNNING
      IPv4        : 192.168.1.200

========================================
Select interface [1-3]: 2

  => Capturing on: eth0
```

### Chế độ truyền tham số trực tiếp (tương thích ngược)

```bash
sudo ./sniffer eth0
```

### Dừng chương trình

Nhấn **Ctrl+C** để dừng và xem báo cáo thống kê:

```
Capture statistics:
  Received: 18432
  Kernel dropped: 0
  Interface dropped: 0
```
