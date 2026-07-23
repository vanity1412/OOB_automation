# OOB Device Manager

OOB Device Manager là ứng dụng local web dùng cho NOC/DC để quản lý thiết bị OOB, console line, inventory và các dấu hiệu cắm nhầm line. Mục tiêu thực tế của tool là giúp operator biết nhanh:

- OOB nào đang quản lý line nào.
- Line nào đang rảnh, đang có người dùng, hoặc có dấu hiệu session treo.
- Console line có khớp inventory hay không.
- Alias trên OOB bị thiếu/sai thì có bằng chứng nào để xác minh thiết bị thật.
- Thiết bị nào mới xuất hiện, đổi line, hoặc đang chiếm line chưa được quản lý.
- Mapping console line với PDU/outlet đã được ghi nhận và xác minh chưa.

Tool được thiết kế theo hướng automation an toàn: ưu tiên scan, đối chiếu, cảnh báo, xác minh thủ công và lưu evidence trước. Các hành động nguy hiểm như tự reboot, tự kick session, tự cấu hình thiết bị production chưa được bật.

## Trạng thái hiện tại

| Nhóm chức năng | Trạng thái | Ghi chú thực tế |
|---|---:|---|
| Quản lý OOB node | Đã có | Khai báo host, vendor/profile, SSH port, note, tags. |
| Scan OOB qua SSH | Đã có | Dùng Netmiko để login OOB và chạy lệnh read-only. |
| Parse console line | Đã có nền | Cisco dùng CLI parser; Vertiv/Avocent ACS800/ACS8000 dùng REST API read-only. Các profile chưa xác minh đã được gỡ khỏi app. |
| Vertiv ACS API scan | Đã bổ sung | Gọi `/access/serialPorts`, `/serialPorts`, `/sessions`, `/system/info`; không gọi power hoặc kill session. |
| Snapshot và lịch sử scan | Đã có | Lưu trạng thái line qua từng lần scan. |
| So sánh inventory | Đã có | Phát hiện đổi line, alias mismatch, thiết bị mới. |
| Miswire detection khi alias thiếu/sai | Đã bổ sung | Có `ALIAS_MISSING`, `UNVERIFIED_LINE`, `LINE_OCCUPIED_BY_UNKNOWN`. |
| Verification workflow | Đã bổ sung | Operator gán line cho device, nhập ticket/note, confidence, verified_by. |
| Session health | Đã bổ sung | Phân loại `ACTIVE_OPERATOR`, `STALE_SESSION`, `NO_OUTPUT`, `BOOTLOADER_OR_ROMMON`, `UNKNOWN_CONTEXT`. |
| Import CSV | Đã có | Preview/diff/add/update inventory. |
| Import Excel | Đã bổ sung | Hỗ trợ `.xlsx`, cần `openpyxl`. |
| Inventory source tracking | Đã bổ sung | Có `source`, `source_id`, `last_imported_at`. |
| Power PDU mapping | Đã bổ sung mức manual | CRUD mapping OOB line với PDU/outlet, chưa có reboot tự động. |
| Quick terminal launcher | Đã có | Mở Windows Terminal/SSH/Telnet/SecureCRT tùy Settings. |
| Scheduled scan | Chưa có | Nên làm sớm để tool thành monitoring thật. |
| Alert Email/Slack/Teams/Zalo | Chưa có | Cần sau khi event ổn định. |
| Credential vault/RBAC | Chưa có | Hiện app cố tình không lưu password thiết bị. |
| Auto login qua console vào BRAS/PE | Chưa nên bật | Nên làm read-only probe sau khi session health và verification ổn. |
| Auto kick session/reboot/config | Chưa bật | Rủi ro cao trong production, chỉ nên thêm sau guardrail nhiều lớp. |

## Tool này dùng để làm gì trong thực tế

Trong môi trường NOC/DC, OOB thường nối console tới BRAS, PE, switch, firewall, server appliance hoặc thiết bị truyền dẫn. Vấn đề thường gặp là:

- Alias trên OOB không được đặt hoặc đặt sai.
- Dây console bị cắm nhầm line sau khi triển khai/bảo trì.
- Inventory nói BRAS-A nằm line 10 nhưng scan thực tế thấy line khác.
- Console line báo busy nhưng không rõ đang có người thao tác hay session cũ bị treo.
- Khi sự cố, operator mất thời gian tìm line, tìm port telnet/SSH, tìm ticket xác minh.
- Mapping giữa console line và PDU outlet không rõ, dễ reboot nhầm thiết bị.

OOB Device Manager giải quyết phần nền của bài toán đó:

1. Scan trạng thái OOB.
2. Lưu snapshot.
3. So sánh với inventory mong đợi.
4. Sinh cảnh báo rõ ràng.
5. Cho operator xác minh bằng ticket/note.
6. Lưu lại evidence để lần sau không phụ thuộc hoàn toàn vào alias.
7. Chuẩn bị dữ liệu sạch trước khi làm automation sâu hơn.

## Khái niệm trong app

| Khái niệm | Ý nghĩa |
|---|---|
| OOB node | Thiết bị console server/terminal server, ví dụ Cisco terminal server hoặc Vertiv/Avocent ACS. |
| Device | Thiết bị thật phía sau console line, ví dụ BRAS, PE, switch, firewall. |
| Console line | Port/line trên OOB đang nối tới thiết bị thật. |
| Alias | Tên line được cấu hình trên OOB. Alias có ích nhưng không nên tin tuyệt đối. |
| Inventory | Danh sách thiết bị mong đợi, line mong đợi, alias mong đợi, site/rack/role. |
| Snapshot | Kết quả scan tại một thời điểm. |
| Verification | Bằng chứng operator đã xác minh line này đúng là thiết bị nào. |
| Confidence | Độ tin cậy của xác minh, theo phần trăm. |
| Power mapping | Mapping thủ công giữa OOB line và PDU/outlet. |

## Workflow vận hành khuyến nghị

### 1. Khai báo OOB

Vào phần quản lý OOB, thêm thiết bị OOB:

- Tên OOB.
- Host/IP quản trị.
- Vendor/profile.
- SSH port.
- Site/rack/tags nếu có.

Password không lưu cố định trong database. Khi scan thật, operator nhập credential theo phiên làm việc.

### 2. Scan OOB

Bấm scan để app SSH vào OOB và chạy lệnh read-only theo profile. App sẽ:

- Lấy danh sách console line.
- Parse line number, alias, trạng thái available/busy, session user nếu có.
- Lưu snapshot.
- Cập nhật bảng detected console.
- Tính session health.
- Sinh alert nếu có mismatch.

### 3. Đối chiếu inventory

App so sánh kết quả scan với inventory đã khai báo/import:

- Device đổi line.
- Alias trên OOB khác expected alias.
- Alias bị thiếu.
- Line có thiết bị nhưng chưa biết là thiết bị nào.
- Line có expected device nhưng chưa có bằng chứng xác minh.

### 4. Xử lý alias thiếu hoặc sai

Khi alias trống/sai, không nên để app tự đoán chắc chắn. Workflow an toàn là:

1. Operator kiểm tra bằng cách mở console hoặc đối chiếu ticket/NMS/CMDB.
2. Nếu xác minh đúng, chọn device tương ứng.
3. Nhập ticket/change reference.
4. Nhập note ngắn: đã xác minh bằng gì.
5. Chọn confidence.
6. Bấm Mark verified hoặc assign line.

Sau bước này, app lưu `verified_by`, `verified_at`, `verification_note`, `verification_ticket`, `verification_confidence`.

### 5. Xử lý session busy

Session busy không đồng nghĩa line đang có người thật. App phân loại health để operator xem trước:

| Health | Ý nghĩa |
|---|---|
| `AVAILABLE_CONFIRMED` | Line đang rảnh theo output OOB. |
| `ACTIVE_OPERATOR` | Có session user rõ ràng, có thể đang có người thao tác. |
| `BUSY_NO_USER` | Busy nhưng chưa thấy user, cần kiểm tra thêm. |
| `STALE_SESSION` | Có dấu hiệu session treo hoặc quá lâu không có output. |
| `NO_OUTPUT` | Không có output đủ để kết luận. |
| `BOOTLOADER_OR_ROMMON` | Có dấu hiệu đang ở bootloader/ROMMON. |
| `UNKNOWN_CONTEXT` | Không đủ dữ liệu để hiểu context. |

Hiện app chỉ phân loại và cho ghi note/mark stale/mark verified. Chưa tự kick session.

### 6. Import inventory

Vào Data, tải template rồi nhập CSV hoặc Excel. Nên chuẩn hóa các cột:

- Device name.
- Site/rack.
- Role/vendor/model nếu có.
- Expected OOB.
- Expected line.
- Expected alias.
- Source/source_id.

Workflow tốt nhất là import từ nguồn đáng tin cậy trước, ví dụ Excel quản lý nội bộ, NetBox, CMDB hoặc NMS export.

### 7. Power mapping

Vào OOB Foundations để tạo mapping:

- OOB.
- Console line.
- Device.
- PDU name/host.
- Outlet label.
- Control mode: `MANUAL`.
- Verification note.

Giai đoạn hiện tại chỉ ghi nhận mapping. Không có nút reboot tự động để tránh rủi ro thao tác nhầm.

### 8. Mở console nhanh

Sau khi device có OOB/line, app có thể mở nhanh terminal theo Settings:

- SSH tới management IP.
- Telnet/reverse telnet tới console port.
- SecureCRT nếu đã cấu hình path.
- Windows Terminal nếu môi trường hỗ trợ.

Các lựa chọn terminal nên để trong Settings để phần Data/Devices không bị dài dòng.

## Các loại cảnh báo quan trọng

| Event | Khi nào xuất hiện | Hành động khuyến nghị |
|---|---|---|
| `NEW_CONSOLE_DEVICE` | Scan thấy line/device mới chưa có trong inventory. | Kiểm tra line, assign device hoặc tạo inventory. |
| `DEVICE_CONSOLE_LINE_CHANGED` | Device đang ở line khác expected line. | Kiểm tra cắm nhầm line hoặc inventory lỗi. |
| `EXPECTED_ALIAS_MISMATCH` | Alias scan khác expected alias. | Kiểm tra alias trên OOB và cập nhật inventory/OOB. |
| `ALIAS_MISSING` | Expected có alias nhưng OOB không trả alias. | Xác minh bằng chứng, không dựa vào alias. |
| `UNVERIFIED_LINE` | Line có expected device nhưng chưa được xác minh. | Operator mark verified kèm ticket/note. |
| `LINE_OCCUPIED_BY_UNKNOWN` | Line busy/occupied nhưng không map được device. | Kiểm tra thủ công, tạo hoặc assign inventory. |

## Chạy app trên Windows

Yêu cầu:

- Python 3.10+.
- Máy chạy app có route/ACL tới IP quản trị OOB.
- OOB cho phép SSH.
- Nếu dùng SecureCRT, cấu hình đường dẫn SecureCRT trong Settings.

Cài package:

```bat
install_windows.bat
```

Chạy app:

```bat
run_windows.bat
```

Mở trình duyệt:

```text
http://127.0.0.1:8501
```

Nếu trình duyệt báo `127.0.0.1 refused connection`, thường là app chưa chạy hoặc Streamlit bị dừng. Chạy lại `run_windows.bat`, đợi cửa sổ báo local URL rồi mở lại link.

## Chạy test

Các test quan trọng:

```bat
.venv\Scripts\python.exe tests\test_parsers.py
.venv\Scripts\python.exe tests\test_change_detection.py
.venv\Scripts\python.exe tests\test_hardening_regressions.py
.venv\Scripts\python.exe tests\test_data_analytics.py
.venv\Scripts\python.exe tests\test_session_health.py
.venv\Scripts\python.exe tests\test_foundation_workflows.py
.venv\Scripts\python.exe tests\test_app_smoke.py
.venv\Scripts\python.exe -m compileall app.py core tests
```

## Đánh giá phần automation nên sửa/đẩy tiếp

### Nên làm sớm

1. Scheduled scan trong UI.
2. Alert ra Email/Slack/Teams/Zalo.
3. Bộ sample output thật theo từng hãng OOB để hoàn thiện parser.
4. Trang review alert tập trung: lọc theo severity, site, OOB, event type, trạng thái đã xử lý/chưa xử lý.
5. Credential handling an toàn hơn: vault, Windows Credential Manager, hoặc nhập theo phiên, không lưu plaintext.
6. RBAC nếu có nhiều người dùng: viewer/operator/admin.
7. Audit trail rõ hơn cho mọi thao tác xác minh, assign line, sửa inventory, sửa power mapping.

### Nên làm sau khi dữ liệu đã sạch

1. NetBox/CMDB/NMS integration.
2. Read-only console probe vào thiết bị thật phía sau OOB.
3. Tự nhận diện hostname/model/serial/version từ console output.
4. Backup config thiết bị thật ở chế độ read-only.
5. Mapping topology OOB -> line -> device -> rack/site -> PDU outlet.

### Chưa nên tự động hóa trực tiếp trong production

1. Tự kick console session.
2. Tự reboot/power-cycle PDU outlet.
3. Tự chạy lệnh cấu hình.
4. Tự sửa mapping line trên OOB.
5. Auto login hàng loạt qua console vào BRAS/PE production.

Các mục này làm được về kỹ thuật, nhưng rủi ro vận hành cao. Nên bắt đầu bằng chế độ gợi ý/manual approval, yêu cầu ticket, hiển thị impact, và lưu audit đầy đủ.

## Roadmap đề xuất

### Phase 1 - Làm dữ liệu đáng tin

- Hoàn thiện miswire detection không phụ thuộc alias.
- Bổ sung verification workflow cho mọi line quan trọng.
- Chuẩn hóa inventory import CSV/Excel.
- Thêm trạng thái xử lý alert.
- Gom evidence theo device/line.

### Phase 2 - Monitoring thật

- Scheduled scan.
- Notification.
- Dashboard theo site/OOB/severity.
- Report thay đổi theo ngày/tuần.
- Retention policy cho snapshot/log.

### Phase 3 - Tích hợp nguồn dữ liệu

- NetBox/CMDB/NMS import.
- So sánh nhiều nguồn inventory.
- Gắn `source`, `source_id`, `last_imported_at` cho từng device.
- Conflict resolution khi nhiều nguồn khác nhau.

### Phase 4 - Probe read-only qua console

- Mở console line ở chế độ read-only.
- Nhận diện prompt/context.
- Chạy lệnh nhẹ như `show version`, `show inventory`.
- Lưu output/evidence.
- Không chạy config/reboot.

### Phase 5 - Guarded automation

- Manual approval bắt buộc.
- Ticket bắt buộc.
- Dry-run trước khi thực thi.
- RBAC.
- Audit đầy đủ.
- Chỉ bật theo site/OOB/device đã verified.

## Nguyên tắc an toàn

- Không tin alias tuyệt đối.
- Không tự sửa production khi chưa có verification.
- Không lưu password thiết bị trong database.
- Không reboot/kick session tự động khi chưa có RBAC, ticket và approval.
- Parser phải có test fixture từ output thật.
- Mọi hành động ảnh hưởng vận hành phải có audit.

## Kết luận

Tool hiện phù hợp nhất để làm nền vận hành OOB: quản lý inventory, scan console line, phát hiện mismatch, xác minh line, phân loại session health và chuẩn bị dữ liệu cho automation. Hướng phát triển đúng là tiếp tục củng cố dữ liệu và cảnh báo trước, sau đó mới đi vào read-only probe, rồi cuối cùng mới cân nhắc automation có tác động như kick session hoặc power-cycle.
