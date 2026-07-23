# Hardening update

Các yêu cầu review đã được xử lý:

- Credential chỉ dùng trong memory; clear Streamlit password state sau connect attempt; scrub Netmiko credential attributes; scan session ngắn hạn.
- Global connect+scan queue/lock; không mở scan SSH song song.
- SSH timeout/retry hữu hạn; authentication failure không retry.
- Parser quality gate; rejected parse không commit state/snapshot/alert và được ghi vào `scan_issues`.
- Mapping/session confidence; mapping parser không tin cậy thì giữ last-known alias và suppress mapping alerts.
- Alert dedup/rate-limit: cùng OOB+line+event type unresolved được update, tăng occurrence count.
- Event precedence để tránh một thay đổi thật sinh nhiều alert trùng.
- GUI bind `127.0.0.1` mặc định bằng `.streamlit/config.toml` và `run_windows.bat`.
- CSV import validate + preview diff + confirmation, safe default Add-only.
- Snapshot/raw retention configurable và auto-prune.
- Audit có actor/source host/source IP.
- Backup manual + Windows Scheduled Task daily 02:00 + backup retention.
- Database migration từ schema Final cũ sang Hardened schema.
