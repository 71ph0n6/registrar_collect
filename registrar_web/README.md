# Registrar & Abuse Email Checker

Web UI đơn giản dựa trên logic RDAP + WHOIS fallback trong script gốc.

## Chạy trên Arch Linux / Linux

Không cần cài Flask hay package Python bên ngoài.

```bash
cd registrar_web
python app.py
```

Mở trình duyệt tại:

```text
http://127.0.0.1:5000
```

Nếu muốn truy cập từ máy khác trong cùng mạng LAN, dùng IP LAN của máy chạy server, ví dụ:

```text
http://192.168.1.20:5000
```

Firewall cần cho phép TCP port 5000 nếu truy cập từ máy khác.

## Cách dùng

1. Dán mỗi URL/domain một dòng.
2. Bấm **Kiểm tra Registrar**.
3. Kết quả được nhóm theo Registrar.
4. Mỗi nhóm hiển thị Abuse Email và danh sách URL.
5. Có nút copy email và copy toàn bộ URL của từng registrar.

## Logic lookup

- RDAP được ưu tiên trước.
- Nếu RDAP có registrar nhưng thiếu abuse email, app thử WHOIS để bổ sung email.
- Nếu RDAP không tìm được registrar, app fallback sang WHOIS.
- Kết quả được cache theo domain trong thời gian server đang chạy.
- Mặc định tối đa 2,000 URL/lần và 4 worker để hạn chế rate limit từ RDAP/WHOIS.
- WHOIS raw cần outbound TCP port 43. Một số VPS/firewall/network chặn port này; khi đó RDAP vẫn có thể hoạt động nhưng WHOIS fallback sẽ không dùng được.
