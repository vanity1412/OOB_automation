# OOB Device Manager — Hardened Final

Bản này ưu tiên an toàn vận hành và tính đúng của dữ liệu trước khi mở rộng troubleshooting.

## Luồng chính

```text
Nhập credential cho 1 scan
        ↓
Global scan lock
        ↓
SSH ngắn hạn tới OOB
        ↓
Read-only discovery
        ↓
Parser quality gate
   ┌────┴─────┐
 FAIL         PASS
   │            │
Lưu issue     Commit current state
Không alert   Save snapshot
Không ghi đè       ↓
               Change detection
                    ↓
               Dedup / rate-limit
                    ↓
                Alert Center
        ↓
Đóng SSH session ngay sau scan
```

## 1. Credential / Password lifecycle

Password **không được lưu trong SQLite, CSV, audit, raw scan hoặc file log của ứng dụng**.

Trong lúc chạy:

1. Người dùng nhập password vào Streamlit password field.
2. Giá trị tồn tại tạm thời trong process memory/widget state của phiên Streamlit để thực hiện connect.
3. Sau authentication, code xóa local reference và scrub các thuộc tính credential phổ biến trên object Netmiko (`password`, `secret`, `passphrase`).
4. Sau mọi connect attempt, app `rerun` và xóa `disc_pass` khỏi Streamlit session state.
5. Scan dùng SSH session ngắn hạn và disconnect ngay sau khi hoàn tất.

Không có cơ chế nào có thể đảm bảo bí mật trước **memory dump/root-level debugging** của chính máy đang chạy ứng dụng. Vì vậy máy chạy tool vẫn phải được xem là máy quản trị tin cậy.

## 2. Không scan song song

Tool dùng global file lock:

```text
data/scan.lock
```

Chỉ **một connect + scan** được chạy tại một thời điểm, kể cả từ nhiều browser session trong cùng server.

Request đến sau sẽ chờ trong hàng đợi ngắn (mặc định tối đa 20 giây) thay vì mở SSH song song.
Nếu vẫn bận quá lâu, request bị từ chối an toàn.

Điều này tránh việc Multi-OOB vô tình tạo nhiều SSH management session đồng thời trên terminal server.

Lock có stale recovery nếu process crash giữa scan.

## 3. SSH timeout / retry

Mặc định profile:

- connect timeout: 8 giây
- auth timeout: 10 giây
- banner timeout: 10 giây
- tối đa 2 connect attempts
- sai credential: **không retry** để tránh account lockout
- show command timeout: 15 giây

Có thể chỉnh trong `profiles/*.json`.

## 4. Parser quality gate

Đây là lớp bảo vệ chống false positive quan trọng nhất.

Nếu:

- `show line` trả CLI error
- có output nhưng parser không parse được line
- số line parse được giảm bất thường so với baseline

thì scan bị:

```text
PARSE_STATUS = REJECTED
```

Và tool **không**:

- ghi đè `detected_console`
- tạo snapshot mới
- tạo change alert

Raw output + lỗi được giữ trong `scans` / `scan_issues` để kiểm tra parser.

### Mapping confidence

Nếu line parser tốt nhưng host/alias parser chưa tin cậy:

- line state vẫn được cập nhật
- last-known alias được giữ lại
- mapping alerts bị tắt cho scan đó

### Viettix

`profiles/viettix.json` mặc định:

```json
"mapping_supported": false
```

Chỉ bật `true` sau khi profile/parser đã được kiểm chứng với output thiết bị Viettix thật.

## 5. Event precedence

Để một sự cố thật không tạo 2–3 alert cùng lúc, mapping event dùng thứ tự ưu tiên:

1. `DEVICE_CONSOLE_LINE_CHANGED`
2. `EXPECTED_ALIAS_MISMATCH`
3. `EXPECTED_DEVICE_NOT_DETECTED`
4. generic `CONSOLE_MAPPING_CHANGED` / `NEW_CONSOLE_DEVICE` / `CONSOLE_LINE_MISSING`

Ví dụ nếu `BRAS01` được kỳ vọng ở line 66 nhưng xuất hiện ở line 72, tool ưu tiên:

```text
DEVICE_CONSOLE_LINE_CHANGED
66 → 72
```

và không tạo thêm mismatch cho cùng thiết bị.

## 6. Alert dedup / rate-limit

Nếu cùng:

```text
OOB + line + event_type + unresolved
```

xuất hiện ở scan sau, tool **update event hiện tại** thay vì tạo alert mới.

Event lưu thêm:

- `last_seen`
- `occurrence_count`
- `new_value` mới nhất

Sau khi event đã `RESOLVED`, nếu tình trạng tái diễn thì mới sinh event mới.

## 7. GUI security

`run_windows.bat` mặc định bind:

```text
127.0.0.1:8501
```

Do đó port Streamlit không listen trực tiếp trên LAN.

Không nên sửa thành `0.0.0.0` trên mạng nội bộ rộng nếu chưa có auth.

Nếu cần chia sẻ cho nhiều người, đặt reverse proxy phía trước có authentication + TLS thay vì expose Streamlit trực tiếp.

## 8. CSV import an toàn

CSV import không apply trực tiếp.

Flow:

```text
Upload
  ↓
Validate schema
  ↓
Validate OOB name / line / duplicate key
  ↓
Preview Diff
  ↓
ADD / UPDATE / UNCHANGED
  ↓
Operator confirm
  ↓
Apply
```

Mặc định:

```text
Add only (safe default)
```

Update existing inventory chỉ chạy khi người dùng chủ động chọn `Apply ADD + UPDATE` và tick xác nhận preview.

## 9. Snapshot retention

Mặc định:

- Console snapshots: 90 ngày
- Raw scan output: 30 ngày

Scanner tự prune sau mỗi accepted scan.

Có thể thay đổi ở tab `Data`.

Change events và audit không tự xóa theo snapshot retention.

## 10. Audit trail

Audit ghi:

- timestamp
- Windows/local actor
- source hostname
- source IP
- action
- OOB ID
- device ID
- detail

Các thao tác Add/Edit/Delete/Acknowledge/Resolve/Import/Backup/Retention đều dùng audit.

## 11. Backup tự động Windows

Manual:

```text
Backup SQLite Now
```

Scheduled daily backup:

```text
setup_daily_backup.bat
```

Tạo Windows Scheduled Task chạy mỗi ngày lúc `02:00`.

Gỡ task:

```text
remove_daily_backup_task.bat
```

Backup files được giữ theo `backup_keep_count` (mặc định 30 file).

## 12. Database

```text
data/oob_manager.db
```

Tables chính:

- `oob_nodes`
- `devices`
- `detected_console`
- `scans`
- `scan_issues`
- `console_snapshots`
- `change_events`
- `audit`
- `app_settings`

## 13. Cisco discovery

```text
show line
show users
show running-config | include ^ip host
show version
show inventory
```

Reverse TCP convention:

```text
2066 → line 66
```

## 14. Viettix

Viettix dùng configurable profile vì CLI có thể khác theo model/version.

Profile:

```text
profiles/viettix.json
```

Raw output luôn được giữ để hiệu chỉnh parser mà không sửa phần database/GUI.

## 15. Cài trên Windows

1. Cài Python 3.10+
2. Chạy:

```text
install_windows.bat
```

3. Chạy tool:

```text
run_windows.bat
```

4. Browser:

```text
http://127.0.0.1:8501
```

5. Nên chạy một lần:

```text
setup_daily_backup.bat
```
