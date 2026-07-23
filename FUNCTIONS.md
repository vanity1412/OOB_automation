# OOB Device Manager Hardened — Checklist chức năng

| # | Chức năng | Trạng thái |
|---|---|---|
| 1 | Multi-OOB inventory | Done |
| 2 | Cisco IOS/IOS-XE profile | Done |
| 3 | Viettix configurable profile | Done |
| 4 | Password không ghi DB/log/disk | Done |
| 5 | Clear password khỏi Streamlit state sau connect attempt | Done |
| 6 | Scrub Netmiko password/secret sau authentication | Done |
| 7 | SSH session ngắn hạn, disconnect sau scan | Done |
| 8 | Global serial scan lock | Done |
| 9 | Stale scan-lock recovery | Done |
| 10 | SSH connect timeout hữu hạn | Done |
| 11 | Retry hữu hạn | Done |
| 12 | Không retry authentication failure | Done |
| 13 | Read-only show/display guard | Done |
| 14 | Cisco console discovery | Done |
| 15 | Raw discovery output | Done |
| 16 | Parser quality gate | Done |
| 17 | Rejected scan không ghi đè current state | Done |
| 18 | Rejected scan không tạo snapshot | Done |
| 19 | Rejected scan không tạo alert | Done |
| 20 | Scan issue database | Done |
| 21 | Mapping confidence flag | Done |
| 22 | Session confidence flag | Done |
| 23 | Last-known mapping preservation khi mapping parser không tin cậy | Done |
| 24 | Console snapshot history | Done |
| 25 | Change detection | Done |
| 26 | Event precedence / overlap suppression | Done |
| 27 | Device moved-line detection | Done |
| 28 | Expected alias mismatch | Done |
| 29 | Expected device missing | Done |
| 30 | Generic mapping change | Done |
| 31 | New unmanaged device detection | Done |
| 32 | Session start/end event | Done |
| 33 | Alert dedup theo OOB+line+event type | Done |
| 34 | Alert occurrence_count / last_seen | Done |
| 35 | Acknowledge / Resolve / Reopen | Done |
| 36 | Audit actor/source host/source IP | Done |
| 37 | Search/filter/device detail | Done |
| 38 | Add/Edit/Delete OOB | Done |
| 39 | Add/Edit/Delete device | Done |
| 40 | CSV schema validation | Done |
| 41 | CSV conflict validation | Done |
| 42 | CSV Preview Diff | Done |
| 43 | Safe Add-only import default | Done |
| 44 | Explicit confirmation before UPDATE import | Done |
| 45 | Snapshot retention policy | Done |
| 46 | Raw scan retention policy | Done |
| 47 | Manual SQLite backup | Done |
| 48 | Scheduled Windows daily backup | Done |
| 49 | Backup retention | Done |
| 50 | GUI bind localhost by default | Done |
| 51 | Data analytics time filter 24h/7d/30d/90d/custom | Done |
| 52 | Daily scan/snapshot/alert/parse-quality summary | Done |
| 53 | Scan volume / accepted-rejected / severity / open-resolved / parse quality charts | Done |
| 54 | Recent scan/issues/events/audit detail tabs | Done |
| 55 | Verified inventory schema foundation | Done |
| 56 | Context-aware terminal schema foundation | Done |
| 57 | Session health schema foundation | Done |
| 58 | Vertiv/Opengear/Raritan disabled vendor profile scaffolds | Done |
| 59 | Safe automation guardrail foundation | Done |
| 60 | Audit ticket_ref/note foundation | Done |
| 61 | Console + power mapping schema foundation | Done |
| 62 | Disaster readiness check schema foundation | Done |
