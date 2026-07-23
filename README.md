# OOB Device Manager Hardened

Ứng dụng này là dashboard quản lý OOB/console server cho môi trường NOC/DC. Mục tiêu chính là:

- Kết nối SSH thật tới thiết bị OOB/terminal server.
- Chạy các lệnh `show`/`display` an toàn để lấy trạng thái console line, alias, user session và snapshot.
- So sánh snapshot giữa các lần scan để phát hiện thay đổi/mismatch.
- Mở nhanh console hoặc management SSH bằng Windows terminal hoặc SecureCRT.
- Lưu inventory, lịch sử scan, cảnh báo, audit và backup trong SQLite cục bộ.

Ứng dụng không lưu password thiết bị vào database, CSV, audit hoặc log của app.

## Kết luận nhanh sau khi đọc code

Ứng dụng có thể dùng với thiết bị thật nếu thiết bị OOB hỗ trợ SSH CLI và profile lệnh/parser phù hợp.

Trạng thái hiện tại:

| Phần | Tình trạng |
|---|---|
| Kết nối SSH thật tới OOB | Có, dùng Netmiko `ConnectHandler` |
| Chạy lệnh `show`/`display` | Có, chỉ cho phép read-only command |
| Cisco IOS/IOS-XE terminal server | Sẵn sàng nhất, profile đã bật mapping |
| Reverse Telnet console `2000 + line` | Có, phù hợp convention Cisco terminal server |
| Mở SecureCRT/Windows terminal | Có, app launch terminal ngoài app |
| Tự cập nhật dashboard sau lệnh show | Có trong luồng `Connect & Scan` của app |
| Tự đọc output người dùng gõ trong SecureCRT | Chưa có, vì SecureCRT đang là cửa sổ ngoài app |
| Viettix/Opengear/Raritan/Vertiv | Có scaffold/profile nền, cần output thật để kiểm chứng parser |
| Tự động cấu hình/reboot/power control | Chưa bật, mới có schema/guardrail nền |

Điểm quan trọng: nếu bạn bấm `Connect & Scan` trong app, app sẽ SSH vào thiết bị OOB, chạy các lệnh show theo profile, parse output và tự cập nhật bảng giám sát. Nếu bạn mở SecureCRT rồi tự gõ lệnh trong cửa sổ SecureCRT, app hiện chưa thể tự đọc ngược output đó để cập nhật dashboard.

## Nguồn đối chiếu Internet

Các quyết định kỹ thuật trong app phù hợp với những nguồn chính thức này:

- [Netmiko](https://ktbyers.github.io/netmiko/) là thư viện multi-vendor để kết nối CLI thiết bị mạng và chạy show/config command.
- [Netmiko API docs](https://ktbyers.github.io/netmiko/docs/netmiko/index.html) mô tả `send_command` dùng `read_timeout` và chờ prompt thiết bị để kết thúc output.
- [Netmiko common issues](https://ktbyers.github.io/netmiko/COMMON_ISSUES.html) ghi nhận `terminal_server` device type cho trường hợp kết nối qua terminal server.
- [Cisco terminal server menu configuration](https://www.cisco.com/c/en/us/support/docs/dial-access/asynchronous-connections/200462-Terminal-server-configuration-using-Menu.html) mô tả port reverse Telnet lấy bằng `2000 + line`.
- [Cisco dialup/reverse Telnet overview](https://www.cisco.com/c/en/us/support/docs/dial-access/dial-on-demand-routing-ddr/10202-chapter16.html) cũng nêu cách Telnet tới port `20yy`, trong đó `yy` là line number.
- [SecureCRT official features](https://www.vandyke.com/products/securecrt/key_features.html) mô tả SecureCRT là terminal emulator hỗ trợ SSH/Telnet, session management, scripting và logging.

## Công nghệ sử dụng

| Thành phần | Vai trò |
|---|---|
| Python | Runtime chính |
| Streamlit | Giao diện web local |
| Netmiko | SSH CLI tới thiết bị mạng/OOB |
| Pandas | Bảng dữ liệu, CSV import/export |
| Altair | Biểu đồ analytics |
| SQLite | Database local |
| Windows batch | Cài đặt, chạy app, backup, mở device |

File dependency:

```text
requirements.txt
```

Nội dung chính:

```text
streamlit==1.60.0
netmiko==4.7.0
pandas>=2.2,<3.0
```

## Cài đặt trên Windows

Yêu cầu:

- Windows có Python 3.10+.
- Máy chạy app phải route/ACL tới IP quản trị của OOB.
- OOB phải cho SSH vào port đã khai báo.
- Nếu muốn mở console bằng Telnet, Windows Telnet Client cần được bật hoặc dùng SecureCRT.
- Nếu muốn mở SecureCRT, cài SecureCRT và cấu hình path trong tab `Settings`.

Cài package:

```bat
install_windows.bat
```

Chạy app thật:

```bat
run_windows.bat
```

Mở trình duyệt:

```text
http://127.0.0.1:8501
```

Mặc định app bind vào `127.0.0.1`, không expose trực tiếp ra LAN. Nếu cần nhiều người dùng, nên đặt reverse proxy có authentication/TLS phía trước, không mở thẳng Streamlit ra mạng nội bộ.

## Chạy demo an toàn

Tạo dữ liệu demo:

```bat
.venv\Scripts\python.exe scripts\seed_demo_data.py
```

Chạy app với database demo:

```bat
run_demo.bat
```

Demo dùng database:

```text
data/demo_oob_manager.db
```

Không bấm `Connect & Scan` trong demo trừ khi đã sửa OOB demo thành IP thiết bị thật.

## Cấu trúc thư mục

```text
app.py                         Streamlit UI chính
core/connection.py             SSH transport Netmiko
core/scanner.py                Chạy lệnh show, parse, quality gate, snapshot, alert
core/discovery.py              Parser output show line/show users/ip host
core/change_detection.py       So sánh snapshot và tạo change event
core/database.py               Schema SQLite, migration, audit, backup
core/repository.py             Hàm đọc/ghi dữ liệu nghiệp vụ
core/viewmodel.py              Ghép inventory + detected state cho UI
core/importer.py               CSV import preview/apply
core/terminal.py               Mở Windows SSH/Telnet/SecureCRT
core/scan_lock.py              Khóa scan toàn cục
profiles/*.json                Profile lệnh theo vendor/OOB
scripts/connect_device.py      CLI mở console/SSH theo hostname/alias/IP
scripts/seed_demo_data.py      Seed dữ liệu demo
tests/*.py                     Smoke/regression tests
data/oob_manager.db            SQLite production mặc định
data/backups/                  Backup SQLite
```

## Các trang trong app

### 1. Devices

Trang giám sát chính.

Hiển thị:

- OOB node.
- Console line.
- Device/alias.
- TCP port console.
- Management IP.
- Trạng thái line: `AVAILABLE`, `BUSY`, `UNKNOWN`.
- User/session đang dùng console nếu parser đọc được.
- Mapping health: `MATCH`, `MISMATCH`, `UNMANAGED`, `NOT DETECTED`, `NO LINE`.
- Verification status: `UNVERIFIED`, `VERIFIED`, `STALE`.
- Last seen.

Thao tác:

- Search hostname/alias/IP/serial/rack/site.
- Filter theo status/mapping/OOB.
- Mở OOB SSH.
- Mở console line bằng Windows Telnet.
- Mở console line bằng SecureCRT Telnet.
- Mở management SSH bằng Windows SSH hoặc SecureCRT SSH.
- Add/Edit inventory.
- Add discovered unmanaged device vào inventory.

### 2. OOB Nodes

Khai báo thiết bị OOB/terminal server thật.

Trường chính:

- OOB name.
- Profile.
- Site.
- IP/hostname.
- SSH port.
- Default username.
- Notes.

Password không khai báo ở đây. Password chỉ nhập tạm ở trang `Discovery`.

### 3. Discovery

Đây là luồng cập nhật dữ liệu từ thiết bị thật.

Workflow:

```text
Chọn OOB
  -> nhập username/password tạm
  -> Connect & Scan
  -> app SSH tới OOB bằng Netmiko
  -> chạy các command show/display trong profile
  -> parse output
  -> quality gate
  -> nếu pass: update detected_console + snapshot + change alerts
  -> nếu reject: chỉ lưu raw output/issue, không ghi đè state hiện tại
  -> disconnect SSH ngay
  -> xóa password khỏi Streamlit session state
```

Với Cisco profile, app thử các nhóm lệnh:

```text
show version
show inventory
show line
show users
show running-config | include ^ip host
show run | include ^ip host
show running-config | include ^menu
show run | include ^menu
```

Các lệnh discovery chỉ cho `show` hoặc `display`. Code chặn lệnh cấu hình/reboot/delete.

Sau scan hợp lệ, dữ liệu tự cập nhật ở:

- Devices dashboard.
- Current detected state.
- Snapshot history.
- Change events.
- Data analytics.

### 4. Changes

Trung tâm cảnh báo thay đổi.

Loại event chính:

- `DEVICE_CONSOLE_LINE_CHANGED`: device được kỳ vọng ở line này nhưng xuất hiện ở line khác.
- `EXPECTED_ALIAS_MISMATCH`: line đúng nhưng alias khác kỳ vọng.
- `EXPECTED_DEVICE_NOT_DETECTED`: device/line kỳ vọng không thấy trong scan hợp lệ.
- `CONSOLE_MAPPING_CHANGED`: mapping line thay đổi so với snapshot trước.
- `NEW_CONSOLE_DEVICE`: có alias mới chưa nằm trong inventory.
- `CONSOLE_LINE_MISSING`: line từng có trong snapshot nhưng scan hiện tại không thấy.
- `CONSOLE_SESSION_STARTED`: line chuyển sang busy.
- `CONSOLE_SESSION_ENDED`: line hết busy.

Có thể:

- Acknowledge.
- Resolve.
- Reopen.
- Ghi note.
- Xem severity/status/occurrence/last_seen.

App có dedup/rate-limit: cùng OOB + line + event type chưa resolved thì update event cũ, không spam event mới.

### 5. Data

Quản lý dữ liệu và vận hành.

Chức năng:

- Export inventory CSV.
- Import inventory CSV có preview diff.
- Backup SQLite ngay.
- Analytics theo `24h`, `7 days`, `30 days`, `90 days`, custom range.
- Xem scan history, scan issues, change events, audit.
- Xem OOB Foundations: verified inventory, terminal context, session health, vendor abstraction, safe automation, power mapping, readiness checks.

### 6. Settings

Quản lý tuỳ chọn vận hành.

Chức năng:

- Terminal Launchers: SecureCRT path, console default, management SSH default.
- Retention & Backups: retention snapshot/raw scan/backup và prune history.

## Profile thiết bị

Profile nằm trong:

```text
profiles/*.json
```

Profile hiện có:

| Profile | Tình trạng |
|---|---|
| `cisco.json` | Sẵn sàng nhất, mapping_supported=true |
| `viettix.json` | Fallback có command candidates, mapping_supported=false |
| `opengear.json` | Scaffold, command rỗng, mapping_supported=false |
| `raritan.json` | Scaffold, command rỗng, mapping_supported=false |
| `vertiv.json` | Scaffold, command rỗng, mapping_supported=false |

Với vendor chưa kiểm chứng, giữ `mapping_supported=false` cho đến khi có output thật và parser đã test. Khi `mapping_supported=false`, app vẫn có thể refresh line/session nếu parse được, nhưng không tạo mapping drift alert dựa trên alias chưa đáng tin.

Ví dụ profile Cisco:

```json
{
  "name": "Cisco IOS / IOS-XE OOB",
  "vendor": "cisco",
  "netmiko_device_type": "cisco_ios",
  "reverse_tcp_base": 2000,
  "mapping_supported": true,
  "command_timeout": 15,
  "connect_timeout": 8,
  "connect_retries": 2
}
```

## Parser và quality gate

App không commit dữ liệu nếu parser có rủi ro tạo false positive.

Scan bị reject khi:

- Không nhận được output console-line.
- Lệnh console-line trả CLI error.
- Có output nhưng parser không đọc được line nào.
- Số line parse được giảm bất thường so với baseline.

Khi scan bị reject, app không:

- Ghi đè `detected_console`.
- Tạo snapshot mới.
- Tạo change alert.

Raw output và lỗi vẫn được lưu trong `scans`/`scan_issues` để chỉnh profile/parser.

## Cập nhật tự động sau lệnh show

Hiện tại có 2 kiểu chạy lệnh:

### A. Lệnh show do app chạy trong `Connect & Scan`

Đây là luồng được hỗ trợ đầy đủ.

Khi bạn bấm `Connect & Scan`, app tự chạy các lệnh show trong profile. Output được parse và dashboard tự cập nhật ngay sau scan nếu pass quality gate.

Đây là cách nên dùng cho monitoring định kỳ hoặc thao tác NOC.

### B. Lệnh show bạn tự gõ trong SecureCRT

App hiện không đọc được output từ cửa sổ SecureCRT ngoài app.

Lý do: app chỉ launch SecureCRT bằng command line. SecureCRT chạy như process độc lập; output không quay về Streamlit/Netmiko session của app.

Nếu yêu cầu bắt buộc là "gõ show trong SecureCRT và app tự cập nhật ngay", cần thêm một trong các hướng mở rộng:

- Viết SecureCRT Python script ghi log/output theo format chuẩn rồi import vào app.
- Bật SecureCRT session logging và thêm watcher/parser đọc log file.
- Xây terminal tích hợp trong app, để app trực tiếp gửi command và nhận output.
- Thêm API endpoint nội bộ để script SecureCRT gửi output về app.

Trong bản hiện tại, workflow đúng là: thao tác tay trong SecureCRT khi cần console, sau đó chạy lại `Connect & Scan` để cập nhật trạng thái giám sát chính thức.

## Kết nối thiết bị thật

Checklist trước khi scan thiết bị thật:

1. Máy chạy app ping/SSH được tới IP OOB.
2. OOB cho phép SSH quản trị.
3. Username có quyền chạy các lệnh show trong profile.
4. Với Cisco terminal server, có `ip host alias 20xx <oob-ip>` hoặc cơ chế mapping tương đương.
5. Line console dùng convention `2000 + line` nếu mở reverse Telnet.
6. `show line` trả output có line TTY/console rõ ràng.
7. `show users` trả session user nếu muốn theo dõi busy/user.
8. `show running-config | include ^ip host` trả alias mapping nếu muốn mapping confidence.
9. Chạy scan đầu tiên để tạo baseline.
10. Chạy scan thứ hai sau thay đổi nhỏ đã biết để xác nhận alert đúng.

Với thiết bị production, nên test bằng một OOB nhỏ/lab trước. Không bật mapping alert cho vendor mới khi parser chưa kiểm chứng.

## Bảo mật credential

Password lifecycle:

```text
Người dùng nhập password ở Discovery
  -> app dùng password để SSH
  -> sau authentication xóa biến local
  -> scrub password/secret/passphrase khỏi object Netmiko
  -> sau connect attempt, rerun Streamlit và clear password field
  -> disconnect SSH sau scan
```

Password không được ghi vào:

- SQLite.
- CSV.
- Audit.
- Raw scan JSON.
- App log do code tạo.

Giới hạn thực tế: không phần mềm user-space nào đảm bảo chống memory dump/root-level debugging trên chính máy chạy app. Máy chạy app vẫn phải là máy quản trị tin cậy.

## Global scan lock

App dùng file lock:

```text
data/scan.lock
```

Chỉ một scan được chạy tại một thời điểm, kể cả khi nhiều browser session mở cùng app. Điều này tránh mở nhiều SSH session song song vào terminal server.

Nếu app crash giữa scan, lock có stale recovery.

## Backup và retention

Database chính:

```text
data/oob_manager.db
```

Backup thủ công:

```bat
run_backup.bat
```

Hoặc trong UI:

```text
Data -> Backup SQLite Now
```

Tạo Windows Scheduled Task backup hằng ngày 02:00:

```bat
setup_daily_backup.bat
```

Gỡ scheduled task:

```bat
remove_daily_backup_task.bat
```

Retention mặc định:

- Console snapshots: 90 ngày.
- Raw scan output: 30 ngày.
- Backup files: 30 file.

Có thể chỉnh trong `Settings -> Retention & Backups`.

## CLI mở nhanh thiết bị

Script:

```bat
connect_device.bat BRAS-HCM-01
```

Hoặc:

```bat
.venv\Scripts\python.exe scripts\connect_device.py BRAS-HCM-01 --dry-run
.venv\Scripts\python.exe scripts\connect_device.py BRAS-HCM-01 --mode console
.venv\Scripts\python.exe scripts\connect_device.py BRAS-HCM-01 --mode mgmt
```

Script tìm theo:

- Hostname inventory.
- Expected alias.
- Management IP.
- Detected alias.

Nếu mode là `console`, script mở OOB host + TCP port đã detect. Nếu mode là `mgmt`, script mở SSH management IP.

## Database tables chính

| Table | Vai trò |
|---|---|
| `oob_nodes` | Danh sách OOB/terminal server |
| `devices` | Inventory thiết bị thật |
| `detected_console` | Trạng thái hiện tại sau scan accepted |
| `scans` | Lịch sử scan và raw JSON |
| `scan_issues` | Parser/transport issue |
| `console_snapshots` | Snapshot từng scan accepted |
| `change_events` | Alert/change event |
| `audit` | Audit thao tác |
| `app_settings` | Retention/launcher settings |
| `terminal_contexts` | Nền tảng phân biệt OOB/target/bootloader |
| `console_power_map` | Nền tảng map console line với PDU/outlet |
| `readiness_checks` | Nền tảng kiểm tra disaster readiness |
| `safe_automation_runs` | Nền tảng guardrail automation |

## Workflow vận hành thực tế

### Onboarding một OOB Cisco terminal server

1. Vào `OOB Nodes`.
2. Add OOB với profile `cisco`.
3. Nhập IP/hostname, SSH port, default username.
4. Vào `Discovery`.
5. Chọn OOB, nhập password tạm.
6. Bấm `Connect & Scan`.
7. Xem raw output nếu scan bị warning/reject.
8. Nếu scan accepted, vào `Devices` xem line/alias/status.
9. Add discovered device vào inventory hoặc import CSV.
10. Chạy scan lần nữa để so sánh expected mapping với detected mapping.

### Theo dõi hằng ngày

1. Mở `Devices` để xem tổng quan line available/busy/mismatch.
2. Mở `Changes` để xử lý alert mới.
3. Khi cần vào console, mở SecureCRT Console hoặc Telnet Console từ device detail.
4. Sau khi thao tác tay xong, chạy `Discovery -> Connect & Scan` để cập nhật trạng thái chính thức.
5. Ghi note khi acknowledge/resolve alert.
6. Kiểm tra `Data -> Analytics` theo 24h/7d/30d.

### Điều tra drift/mismatch

1. Xem alert trong `Changes`.
2. Mở detail để xem old/new value, line, device, occurrence_count.
3. Mở console hoặc management SSH nếu cần xác minh.
4. Nếu inventory sai, sửa device expected line/alias.
5. Nếu parser sai, xem `Raw discovery output` hoặc `Scan Issues`.
6. Chạy lại scan.
7. Resolve alert khi trạng thái đã đúng.

### Import inventory hàng loạt

1. Chuẩn bị CSV có các cột như sample `data/samples/oob_inventory_sample.csv`.
2. Vào `Data`.
3. Upload CSV.
4. Xem preview diff.
5. Mặc định dùng `Add only`.
6. Chỉ chọn `Apply ADD + UPDATE` khi đã review diff.
7. Apply.
8. Chạy scan để đối chiếu inventory với thực tế.

## Ứng dụng thực tế

Ứng dụng phù hợp cho:

- NOC theo dõi nhiều console server/OOB.
- DC kiểm tra thiết bị nào đang cắm vào line nào.
- Phát hiện cắm nhầm console line.
- Phát hiện thiết bị unmanaged xuất hiện trên console server.
- Biết line nào đang busy và user/session nào đang dùng.
- Lưu baseline trước/sau bảo trì.
- Audit thao tác mở terminal, scan, import, backup, acknowledge/resolve alert.
- Chuẩn bị disaster recovery: biết console line, management IP, rack/U, OOB node, PDU mapping nền.
- Chuẩn hóa workflow trước khi mở automation nguy hiểm.

Ứng dụng chưa phù hợp để thay thế hoàn toàn:

- SecureCRT terminal emulator đầy đủ.
- Tool cấu hình hàng loạt.
- Tool reboot/power-cycle tự động.
- SIEM/syslog collector thời gian thực.
- Nền tảng multi-user có phân quyền, nếu chỉ chạy Streamlit local mặc định.

## Kiểm thử

Các test hiện có nằm trong:

```text
tests/
```

Chạy smoke/regression thủ công:

```bat
.venv\Scripts\python.exe tests\test_parsers.py
.venv\Scripts\python.exe tests\test_change_detection.py
.venv\Scripts\python.exe tests\test_hardening_regressions.py
.venv\Scripts\python.exe tests\test_data_analytics.py
.venv\Scripts\python.exe tests\test_app_smoke.py
```

Checklist UI demo:

```text
data/samples/manual_test_checklist.md
```

## Hướng mở rộng nên làm tiếp

Ưu tiên nếu muốn tiến gần SecureCRT hơn:

1. Tích hợp terminal trong app hoặc script SecureCRT để app nhận output thật của lệnh người dùng gõ.
2. Thêm parser `show version`/`show inventory` để tự cập nhật verified hostname/model/serial.
3. Thêm profile thật cho Viettix/Opengear/Raritan/Vertiv từ output production.
4. Thêm scheduler scan có credential vault hoặc prompt-on-demand, không lưu plaintext password.
5. Thêm export report PDF/CSV cho alert và snapshot.
6. Thêm role/auth nếu muốn dùng nhiều người qua LAN.
7. Thêm read-only API để tích hợp NOC/SIEM.

## Nguyên tắc an toàn khi mở rộng

- Mặc định chỉ chạy `show`/`display`.
- Không lưu password plaintext.
- Không bật mapping alert cho vendor chưa kiểm chứng parser.
- Không ghi đè state khi parser reject.
- Không chạy nhiều SSH scan song song vào OOB.
- Không expose Streamlit trực tiếp ra LAN nếu chưa có authentication.
- Không tự động reboot/power-cycle khi chưa có context guard, ticket, xác nhận và mapping PDU đã verified.
