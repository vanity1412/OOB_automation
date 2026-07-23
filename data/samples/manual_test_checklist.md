# Manual test sample

Use the demo app URL and the demo database. The data is safe to reset.

1. Open Devices.
2. Search `PE-HCM-02`.
3. Confirm the row shows `BUSY` and session user `operator1`.
4. Filter `UNMANAGED`.
5. Confirm `UNMANAGED-FW` appears on line 68.
6. Open Changes.
7. Select the HIGH alert and click Acknowledge, then Resolve.
8. Open Data.
9. Upload `data/samples/oob_inventory_sample.csv`.
10. Confirm preview shows ADD/UPDATE/UNCHANGED before applying.
11. Run `.venv\Scripts\python.exe scripts\connect_device.py BRAS-HCM-01 --dry-run`.
12. Confirm it resolves `BRAS-HCM-01` to OOB console port `2066`.
13. Run `.venv\Scripts\python.exe scripts\connect_device.py BRAS-HCM-01 --mode mgmt --dry-run`.
14. Confirm it resolves to management SSH target `172.16.10.11`.
15. Open Discovery.
16. Do not use Connect & Scan unless you point the OOB record to a real reachable device.
