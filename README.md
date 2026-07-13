# AF_PACKET Packet Sniffer (libpcap)

Một module thu thập và phân tích gói tin ở tầng liên kết dữ liệu (Layer 2 - AF_PACKET) sử dụng ngôn ngữ C và thư viện `libpcap` phiên bản hiện đại trên Linux.

## Tính năng nổi bật

- **Kiến trúc Modern libpcap**: Sử dụng chuỗi hàm hiện đại `pcap_create()`, `pcap_set_immediate_mode()`, `pcap_set_promisc()` và `pcap_activate()` thay vì hàm cũ đã lỗi thời `pcap_open_live()`.
- **Phân tích gói tin nhiều tầng (Layer-by-Layer)**:
  - **Layer 2 (Ethernet)**: Trích xuất địa chỉ MAC nguồn/đích và EtherType.
  - **Layer 3 (IPv4)**: Trích xuất địa chỉ IP nguồn/đích, Protocol. Bỏ qua IPv6 và các fragment không phải gói đầu.
  - **Layer 4 (TCP/UDP)**: Trích xuất Port nguồn/đích.
  - **Payload**: In thông tin kích thước payload và hiển thị preview 16 byte đầu dưới dạng Hexadecimal.
- **Xử lý tín hiệu an toàn**: Bắt tín hiệu `SIGINT` (Ctrl+C) để ngắt vòng lặp bắt gói tin (`pcap_breakloop()`) một cách an toàn và hiển thị bảng thống kê lưu lượng (`ps_recv`, `ps_drop`, `ps_ifdrop`).
- **An toàn bộ nhớ**: Kiểm tra biên (boundary checking) nghiêm ngặt kích thước gói thực tế nhận được (`caplen`) trước khi ép kiểu cấu trúc dữ liệu để tránh lỗi tràn bộ đệm (buffer overflow).

## Cấu trúc mã nguồn

Mã nguồn được phân tách module rõ ràng:
- `parse_ethernet()`: Phân tích Ethernet header.
- `parse_ipv4()`: Phân tích IPv4 header.
- `parse_tcp()`: Phân tích TCP header.
- `parse_udp()`: Phân tích UDP header.
- `packet_handler()`: Hàm callback điều phối của `pcap_loop`.
- `on_sigint()`: Bộ xử lý tín hiệu hệ thống để dừng an toàn.

## Hướng dẫn cài đặt và chạy thử

### 1. Cài đặt thư viện phát triển pcap
Trên các hệ điều hành Ubuntu/Debian/Kali Linux:
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev
```

### 2. Biên dịch chương trình
Sử dụng trình biên dịch GCC với tiêu chuẩn C11:
```bash
gcc -std=c11 -Wall -Wextra -Wpedantic sniffer.c -o sniffer -lpcap
```

### 3. Chạy ứng dụng
Do chương trình sử dụng Raw Socket (`AF_PACKET`) ở Layer 2 nên cần chạy với quyền quản trị viên (`sudo`):
```bash
# Xem danh sách card mạng đang hoạt động
ip link

# Chạy sniffer trên card mạng mong muốn (ví dụ: eth0)
sudo ./sniffer eth0
```

### 4. Dừng chương trình
Nhấn tổ hợp phím **`Ctrl + C`** để dừng bắt gói tin và xem báo cáo thống kê.
