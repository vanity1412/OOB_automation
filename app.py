from __future__ import annotations

import html
import json
import sqlite3

import altair as alt
import pandas as pd
import streamlit as st
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from core.connection import LiveOOB
from core.database import audit, backup_db, init_db, prune_backups
from core.importer import apply_inventory_import, preview_inventory_import
from core.profiles import list_profiles, load_profile, save_profile
from core.repository import (
    count_open_events,
    delete_device,
    delete_oob,
    get_device,
    get_oob,
    get_setting,
    history_summary,
    list_audit,
    list_change_events,
    list_devices,
    list_oobs,
    list_scan_issues,
    list_scans,
    list_snapshots,
    prune_history,
    save_device,
    save_oob,
    set_setting,
    update_change_event_status,
)
from core.scan_lock import ScanBusyError, global_scan_lock
from core.scanner import scan
from core.terminal import (
    launch_securecrt_ssh,
    launch_securecrt_telnet,
    launch_windows_ssh,
    launch_windows_telnet,
)
from core.viewmodel import build_rows


st.set_page_config(
    page_title="OOB Device Manager",
    page_icon="🖧",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# Streamlit widget state lives in server memory. Password is cleared immediately
# after every connection attempt via a rerun; it is never written to SQLite/logs.
if st.session_state.pop("_clear_disc_pass", False):
    st.session_state["disc_pass"] = ""

_flash_success = st.session_state.pop("_flash_success", None)
_flash_error = st.session_state.pop("_flash_error", None)
_flash_warning = st.session_state.pop("_flash_warning", None)

st.markdown("""
<style>
:root {
  --bg: #f6f8fb;
  --surface: #ffffff;
  --surface-soft: #f9fbfd;
  --text: #172033;
  --muted: #607089;
  --line: #d9e2ef;
  --blue: #2563eb;
  --green: #16803c;
  --amber: #b45309;
  --red: #b42318;
  --violet: #6d28d9;
  --cyan: #087b8f;
}
.stApp {
  background: linear-gradient(180deg, #f4f8ff 0%, var(--bg) 260px);
  color: var(--text);
}
[data-testid="stSidebar"] {
  background: #0f172a;
  border-right: 1px solid #1e293b;
}
[data-testid="stSidebar"] * {
  color: #e5eaf2;
}
[data-testid="stSidebar"] [role="radiogroup"] label {
  border: 1px solid rgba(148, 163, 184, .18);
  border-radius: 8px;
  padding: 8px 10px;
  margin: 4px 0;
  background: rgba(255, 255, 255, .035);
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child > div:first-child {
  display: none;
}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {
  background: rgba(37, 99, 235, .22);
  border-color: rgba(96, 165, 250, .55);
}
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"],
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: rgba(37, 99, 235, .34);
  border-color: rgba(96, 165, 250, .82);
  box-shadow: inset 4px 0 0 #22d3ee;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
  color: #cbd5e1;
}
.block-container {
  max-width: 1480px;
  padding-top: 1.1rem;
  padding-bottom: 2rem;
}
h1 {
  font-size: 2rem !important;
  margin-bottom: .2rem !important;
  color: var(--text);
  letter-spacing: 0 !important;
}
h2 {font-size: 1.35rem !important;}
h3 {font-size: 1.05rem !important;}
div[data-testid="stMetric"] {
  border:1px solid var(--line);
  border-radius:8px;
  padding:10px 13px;
  background:var(--surface);
  box-shadow: 0 8px 22px rgba(23, 32, 51, .06);
}
div[data-testid="stDataFrame"] {
  border:1px solid var(--line);
  border-radius:8px;
  overflow:hidden;
  box-shadow: 0 8px 22px rgba(23, 32, 51, .04);
}
[data-testid="stForm"] {
  border:1px solid var(--line);
  border-radius:8px;
  padding:14px;
  background: var(--surface);
}
.small-card {
  border:1px solid var(--line);
  border-radius:8px;
  padding:12px 14px;
  background:var(--surface);
  box-shadow: 0 8px 22px rgba(23, 32, 51, .05);
}
.muted {color: var(--muted);}
.kpi-card {
  min-height: 92px;
  border: 1px solid var(--line);
  border-left: 6px solid var(--accent);
  border-radius: 8px;
  padding: 12px 14px;
  background: var(--surface);
  box-shadow: 0 10px 24px rgba(23, 32, 51, .07);
}
.kpi-label {
  color: var(--muted);
  font-size: .78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0;
}
.kpi-value {
  color: var(--text);
  font-size: 1.75rem;
  font-weight: 800;
  line-height: 1.15;
  margin-top: 4px;
}
.kpi-caption {
  color: var(--muted);
  font-size: .78rem;
  margin-top: 4px;
}
.status-strip {
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin: 2px 0 14px;
}
.pill {
  display:inline-flex;
  align-items:center;
  gap:7px;
  border: 1px solid var(--pill-border);
  border-radius: 999px;
  padding: 5px 10px;
  color: var(--pill-text);
  background: var(--pill-bg);
  font-size: .82rem;
  font-weight: 700;
}
.pill-dot {
  width:8px;
  height:8px;
  border-radius:999px;
  background: var(--pill-text);
}
.section-note {
  border: 1px solid #c7d2fe;
  border-left: 6px solid var(--blue);
  border-radius: 8px;
  padding: 10px 12px;
  background: #eef4ff;
  color: #1d3b7a;
  font-size: .9rem;
}
.chart-panel {
  border:1px solid var(--line);
  border-radius:8px;
  background: var(--surface);
  padding: 10px 12px 4px;
  box-shadow: 0 8px 22px rgba(23, 32, 51, .05);
}
.chart-title {
  color: var(--muted);
  font-size: .78rem;
  font-weight: 800;
  text-transform: uppercase;
  margin-bottom: 4px;
}
.sidebar-brand {
  padding: 10px 4px 14px;
  border-bottom: 1px solid rgba(148, 163, 184, .24);
  margin-bottom: 10px;
}
.sidebar-brand-title {
  color: #f8fafc;
  font-size: 1.05rem;
  font-weight: 900;
}
.sidebar-brand-subtitle {
  color: #94a3b8;
  font-size: .78rem;
  margin-top: 3px;
}
.sidebar-mini {
  border: 1px solid rgba(148, 163, 184, .20);
  border-radius: 8px;
  padding: 8px 10px;
  background: rgba(255, 255, 255, .04);
  margin-top: 8px;
}
.sidebar-mini b {
  color: #f8fafc;
}
.sidebar-mini span {
  color: #94a3b8;
  font-size: .74rem;
  text-transform: uppercase;
  font-weight: 800;
}
@media(max-width:900px){
  .block-container{
    padding-left:.65rem;
    padding-right:.65rem;
  }
}
</style>
""", unsafe_allow_html=True)

TONE_THEME = {
    "blue": ("#dbeafe", "#1d4ed8", "#93c5fd"),
    "green": ("#dcfce7", "#166534", "#86efac"),
    "amber": ("#fef3c7", "#92400e", "#facc15"),
    "red": ("#fee2e2", "#991b1b", "#fca5a5"),
    "violet": ("#ede9fe", "#5b21b6", "#c4b5fd"),
    "cyan": ("#cffafe", "#155e75", "#67e8f9"),
    "slate": ("#e2e8f0", "#334155", "#cbd5e1"),
}

VALUE_TONES = {
    "AVAILABLE": "green",
    "BUSY": "amber",
    "UNKNOWN": "slate",
    "MATCH": "green",
    "MISMATCH": "red",
    "UNMANAGED": "violet",
    "NOT DETECTED": "red",
    "NO LINE": "slate",
    "NEW": "red",
    "ACKNOWLEDGED": "amber",
    "RESOLVED": "green",
    "CRITICAL": "red",
    "HIGH": "red",
    "WARNING": "amber",
    "INFO": "blue",
    "ACCEPTED": "green",
    "REJECTED": "red",
    "ERROR": "red",
    "ADD": "green",
    "UPDATE": "amber",
    "UNCHANGED": "slate",
    "OPEN": "red",
    "DETECTED": "blue",
    "SCANS": "cyan",
    "SNAPSHOTS": "violet",
    "EVENTS": "amber",
    "OPEN EVENTS": "red",
}


def tone_vars(tone: str) -> str:
    bg, text, border = TONE_THEME.get(tone, TONE_THEME["slate"])
    return f"--pill-bg:{bg}; --pill-text:{text}; --pill-border:{border};"


def render_kpi(container, label: str, value: object, tone: str, caption: str = "") -> None:
    _, text, _ = TONE_THEME.get(tone, TONE_THEME["slate"])
    container.markdown(
        "<div class='kpi-card' style='--accent:{accent};'>"
        "<div class='kpi-label'>{label}</div>"
        "<div class='kpi-value'>{value}</div>"
        "<div class='kpi-caption'>{caption}</div>"
        "</div>".format(
            accent=text,
            label=html.escape(str(label)),
            value=html.escape(str(value)),
            caption=html.escape(str(caption)),
        ),
        unsafe_allow_html=True,
    )


def pill(label: str, tone: str) -> str:
    return (
        f"<span class='pill' style='{tone_vars(tone)}'>"
        f"<span class='pill-dot'></span>{html.escape(str(label))}</span>"
    )


def render_status_strip(items: list[tuple[str, str]]) -> None:
    st.markdown(
        "<div class='status-strip'>" + "".join(pill(label, tone) for label, tone in items) + "</div>",
        unsafe_allow_html=True,
    )


def tone_color(value: object) -> str:
    key = str(value or "").strip().upper()
    tone = VALUE_TONES.get(key, "blue")
    _, text, _ = TONE_THEME.get(tone, TONE_THEME["blue"])
    return text


def render_bar_chart(
    container,
    title: str,
    rows: list[tuple[str, int]],
    *,
    height: int = 160,
) -> None:
    frame = pd.DataFrame(
        [{"label": label, "count": int(count), "color": tone_color(label)} for label, count in rows]
    )
    with container:
        st.markdown(
            f"<div class='chart-panel'><div class='chart-title'>{html.escape(title)}</div>",
            unsafe_allow_html=True,
        )
        if frame.empty or int(frame["count"].sum()) == 0:
            st.caption("No data")
        else:
            max_count = max(1, int(frame["count"].max()))
            chart = (
                alt.Chart(frame)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                .encode(
                    x=alt.X("label:N", title=None, sort=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y(
                        "count:Q",
                        title=None,
                        scale=alt.Scale(domain=[0, max_count]),
                        axis=alt.Axis(values=list(range(max_count + 1)), format="d"),
                    ),
                    color=alt.Color("color:N", scale=None, legend=None),
                    tooltip=[
                        alt.Tooltip("label:N", title="Type"),
                        alt.Tooltip("count:Q", title="Count"),
                    ],
                )
                .properties(height=height)
            )
            st.altair_chart(chart, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


def count_rows(frame: pd.DataFrame, column: str) -> list[tuple[str, int]]:
    if frame.empty or column not in frame.columns:
        return []
    counts = (
        frame[column]
        .fillna("UNKNOWN")
        .astype(str)
        .str.strip()
        .str.upper()
        .replace("", "UNKNOWN")
        .value_counts()
    )
    return [(str(label), int(count)) for label, count in counts.items()]


def cell_style(value: object) -> str:
    key = str(value or "").strip().upper()
    tone = VALUE_TONES.get(key)
    if not tone:
        return ""
    bg, text, border = TONE_THEME[tone]
    return (
        f"background-color:{bg}; color:{text}; font-weight:800; "
        f"border-left:4px solid {border};"
    )


def row_tint(row: pd.Series) -> list[str]:
    mapping = str(row.get("Mapping", "") or "").upper()
    status = str(row.get("Status", "") or "").upper()
    severity = str(row.get("severity", "") or "").upper()
    action = str(row.get("action", "") or "").upper()

    bg = ""
    if mapping in {"MISMATCH", "NOT DETECTED"} or severity in {"CRITICAL", "HIGH"}:
        bg = "background-color:#fff5f5;"
    elif mapping == "UNMANAGED" or status == "BUSY" or severity == "WARNING" or action == "UPDATE":
        bg = "background-color:#fffbeb;"
    elif status == "AVAILABLE" or action == "ADD":
        bg = "background-color:#f0fdf4;"
    elif action == "UNCHANGED":
        bg = "background-color:#f8fafc;"
    return [bg for _ in row]


def styled_table(frame: pd.DataFrame):
    styled = (
        frame.style.apply(row_tint, axis=1)
        .set_properties(**{"border-color": "#d9e2ef"})
        .set_table_styles(
            [
                {
                    "selector": "th",
                    "props": [
                        ("background-color", "#eef4ff"),
                        ("color", "#1e3a8a"),
                        ("font-weight", "800"),
                        ("border-bottom", "1px solid #c7d2fe"),
                    ],
                },
                {
                    "selector": "td",
                    "props": [
                        ("border-bottom", "1px solid #e5eaf2"),
                    ],
                },
            ]
        )
    )
    highlight_cols = [
        col
        for col in ("Status", "Mapping", "severity", "status", "state", "parse_status", "action")
        if col in frame.columns
    ]
    for col in highlight_cols:
        styled = styled.map(cell_style, subset=[col])
    return styled


def has_value(value: object) -> bool:
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return bool(str(value).strip())


def as_port(value: object) -> int:
    return int(float(str(value).strip()))


DEVICE_COLUMN_CONFIG = {
    "OOB": st.column_config.TextColumn("OOB", width="medium"),
    "Line": st.column_config.NumberColumn("Line", width="small"),
    "Device": st.column_config.TextColumn("Device", width="medium"),
    "Type": st.column_config.TextColumn("Type", width="small"),
    "Mgmt IP": st.column_config.TextColumn("Mgmt IP", width="medium"),
    "Alias": st.column_config.TextColumn("Alias", width="medium"),
    "Status": st.column_config.TextColumn("Status", width="small"),
    "Session": st.column_config.TextColumn("Session", width="small"),
    "Mapping": st.column_config.TextColumn("Mapping", width="medium"),
    "Last Seen": st.column_config.TextColumn("Last Seen", width="medium"),
}


if _flash_success:
    st.success(_flash_success)
if _flash_warning:
    st.warning(_flash_warning)
if _flash_error:
    st.error(_flash_error)

if "live" not in st.session_state:
    st.session_state.live = LiveOOB()
if "last_scan" not in st.session_state:
    st.session_state.last_scan = None
if "device_edit_id" not in st.session_state:
    st.session_state.device_edit_id = None
if "oob_edit_id" not in st.session_state:
    st.session_state.oob_edit_id = None

live: LiveOOB = st.session_state.live
profiles = list_profiles()
oobs = list_oobs()

header_alerts = count_open_events()
header_open_alerts = sum(header_alerts.values())

nav_items = {
    "▦  Devices": "Devices",
    "▣  OOB Nodes": "OOB Nodes",
    "⚠  Changes": "Changes",
    "↻  Discovery": "Discovery",
    "▤  Data": "Data",
}

with st.sidebar:
    st.markdown(
        "<div class='sidebar-brand'>"
        "<div class='sidebar-brand-title'>OOB Manager</div>"
        "<div class='sidebar-brand-subtitle'>NOC operations dashboard</div>"
        "</div>",
        unsafe_allow_html=True,
    )
    selected_nav = st.radio(
        "Navigation",
        list(nav_items.keys()),
        label_visibility="collapsed",
        key="main_nav",
    )
    active_page = nav_items[selected_nav]
    live_badge = pill(f"Connected: {live.name}", "green") if live.connected else pill("Disconnected", "slate")
    st.markdown(live_badge, unsafe_allow_html=True)
    st.markdown(
        "<div class='sidebar-mini'><span>OOB Nodes</span><br><b>{oob_count}</b></div>"
        "<div class='sidebar-mini'><span>Open Alerts</span><br><b>{alert_count}</b></div>"
        "<div class='sidebar-mini'><span>Scan Mode</span><br><b>Serial lock</b></div>".format(
            oob_count=len(oobs),
            alert_count=header_open_alerts,
        ),
        unsafe_allow_html=True,
    )

# ---------- Header ----------
left, right = st.columns([4, 1.3])
with left:
    st.title(active_page)
    if live.connected:
        st.caption(f"Connected · {live.name} · {live.host}:{live.port}")
    else:
        st.caption("NOC dashboard · OOB console control")
with right:
    if live.connected:
        if st.button("Disconnect", use_container_width=True):
            audit("disconnect", oob_id=live.oob_id, detail=live.host)
            live.disconnect()
            st.rerun()

render_status_strip(
    [
        ("Local GUI", "green"),
        (f"{len(oobs)} OOB node" + ("" if len(oobs) == 1 else "s"), "blue"),
        (
            f"{header_open_alerts} open alert" + ("" if header_open_alerts == 1 else "s"),
            "red" if header_open_alerts else "green",
        ),
        ("Scan lock", "cyan"),
        ("No saved passwords", "violet"),
    ]
)

# ==============================================================
# DEVICES
# ==============================================================
if active_page == "Devices":
    rows = build_rows()
    df = pd.DataFrame(rows)
    alert_counts = count_open_events()

    total = len(df) if not df.empty else 0
    available = int((df["Status"] == "AVAILABLE").sum()) if not df.empty else 0
    busy = int((df["Status"] == "BUSY").sum()) if not df.empty else 0
    mismatch = int((df["Mapping"] == "MISMATCH").sum()) if not df.empty else 0
    open_alerts = sum(alert_counts.values())

    m1,m2,m3,m4,m5 = st.columns(5)
    render_kpi(m1, "Devices / Lines", total, "blue", "inventory + detected")
    render_kpi(m2, "Available", available, "green", "ready console")
    render_kpi(m3, "Busy", busy, "amber", "active sessions")
    render_kpi(m4, "Mismatch", mismatch, "red" if mismatch else "green", "mapping drift")
    render_kpi(m5, "Open Alerts", open_alerts, "red" if open_alerts else "green", "needs attention")

    if not df.empty:
        chart1, chart2 = st.columns(2)
        render_bar_chart(chart1, "Console Status", count_rows(df, "Status"))
        render_bar_chart(chart2, "Mapping Health", count_rows(df, "Mapping"))

    b1,b2,b3,b4 = st.columns([4,1.6,1.7,1.2])
    with b1:
        q = st.text_input(
            "Search",
            placeholder="Hostname / alias / IP / line / serial / rack / site...",
            label_visibility="collapsed",
        )
    with b2:
        filt = st.selectbox(
            "Filter",
            ["All","AVAILABLE","BUSY","UNKNOWN","MISMATCH","UNMANAGED","NOT DETECTED","NO LINE"],
            label_visibility="collapsed",
        )
    with b3:
        oob_filter = st.selectbox(
            "OOB filter",
            ["All"] + [x["name"] for x in oobs],
            label_visibility="collapsed",
        )
    with b4:
        if st.button("+ Device", use_container_width=True):
            st.session_state.device_edit_id = -1

    shown = df.copy()

    if not shown.empty:
        if q.strip():
            needle = q.strip().lower()
            cols = ["Device","Alias","Line","Mgmt IP","Serial","Rack","Site","Type","OOB"]
            mask = pd.Series(False, index=shown.index)
            for col in cols:
                mask |= (
                    shown[col]
                    .fillna("")
                    .astype(str)
                    .str.lower()
                    .str.contains(needle, regex=False)
                )
            shown = shown[mask]

        if filt != "All":
            if filt in {"MISMATCH","UNMANAGED","NOT DETECTED","NO LINE"}:
                shown = shown[shown["Mapping"] == filt]
            else:
                shown = shown[shown["Status"] == filt]

        if oob_filter != "All":
            shown = shown[shown["OOB"] == oob_filter]

    table_cols = [
        "OOB","Line","Device","Type","Mgmt IP",
        "Alias","Status","Session","Mapping","Last Seen"
    ]

    if shown.empty:
        st.info("No data. Add OOB, then Connect & Scan.")
    else:
        st.dataframe(
            styled_table(shown[table_cols]),
            use_container_width=True,
            hide_index=True,
            column_config=DEVICE_COLUMN_CONFIG,
            height=min(560, 72 + len(shown) * 35),
        )

        labels = {
            f"{r['Device']} · {r['OOB']} · Line {r['Line'] if pd.notna(r['Line']) else '-'}": r
            for r in shown.to_dict("records")
        }
        selected_label = st.selectbox(
            "Device detail",
            list(labels.keys()),
            label_visibility="collapsed",
        )
        row = labels[selected_label]

        c1,c2 = st.columns([2.25,1], gap="large")

        with c1:
            device_html = html.escape(str(row["Device"]))
            meta_html = html.escape(
                f"{row['Type'] or '-'} - {row['Site'] or '-'} - {row['Rack'] or '-'}"
            )
            st.markdown(
                f"<div class='small-card'><b>{device_html}</b><br>"
                f"<span class='muted'>{meta_html}</span></div>",
                unsafe_allow_html=True,
            )
            detail = pd.DataFrame([
                ["OOB", row["OOB"]],
                ["Console Line", row["Line"]],
                ["Alias", row["Alias"] or "-"],
                ["TCP Port", row["TCP Port"] or "-"],
                ["Console Status", row["Status"]],
                ["Session", row["Session"] or "-"],
                ["Mapping", row["Mapping"]],
                ["Mgmt IP", row["Mgmt IP"] or "-"],
                ["Vendor/Model", f"{row['Vendor']} {row['Model']}".strip() or "-"],
                ["Serial", row["Serial"] or "-"],
                ["Last Seen", row["Last Seen"] or "-"],
            ], columns=["Field","Value"])
            st.dataframe(
                detail.astype(str),
                use_container_width=True,
                hide_index=True,
                height=390,
            )

        with c2:
            st.write("**Actions**")

            if row["Status"] == "BUSY":
                st.warning(f"Console line đang BUSY · {row['Session'] or 'unknown user'}")
            elif row["Status"] == "AVAILABLE":
                st.success("Console line available.")
            else:
                st.info(f"Console state: {row['Status']}")

            if row["Alias"]:
                st.code(str(row["Alias"]), language="text")
                st.caption("Login alias")

            target_oob = next((x for x in oobs if x["id"] == row["OOBID"]), None)
            securecrt_path = get_setting("securecrt_path", "SecureCRT.exe")
            console_launcher = get_setting("console_launcher", "Windows Telnet")
            mgmt_launcher = get_setting("mgmt_launcher", "Windows SSH")
            if target_oob:
                if st.button("Open OOB SSH", use_container_width=True):
                    try:
                        launch_windows_ssh(
                            target_oob["host"],
                            target_oob["port"],
                            target_oob["username"],
                        )
                        audit(
                            "launch_terminal",
                            oob_id=target_oob["id"],
                            device_id=row["DeviceID"],
                            detail=row["Device"],
                        )
                        st.toast("Đã mở PowerShell SSH terminal.", icon="🖥️")
                    except Exception as exc:
                        st.error(str(exc))

            if has_value(row["TCP Port"]) and has_value(row["OOB Host"]):
                tcp_port = as_port(row["TCP Port"])
                st.code(
                    f"telnet {row['OOB Host']} {tcp_port}",
                    language="powershell",
                )
                ctel1, ctel2 = st.columns(2)
                if ctel1.button("Telnet Console", use_container_width=True):
                    try:
                        launch_windows_telnet(row["OOB Host"], tcp_port)
                        audit(
                            "launch_telnet_console",
                            oob_id=row["OOBID"],
                            device_id=row["DeviceID"],
                            detail=f"{row['Device']}:{tcp_port}",
                        )
                        st.toast("Console telnet opened.")
                    except Exception as exc:
                        st.error(str(exc))
                if ctel2.button("SecureCRT Console", use_container_width=True):
                    try:
                        launch_securecrt_telnet(row["OOB Host"], tcp_port, securecrt_path)
                        audit(
                            "launch_securecrt_console",
                            oob_id=row["OOBID"],
                            device_id=row["DeviceID"],
                            detail=f"{row['Device']}:{tcp_port}",
                        )
                        st.toast("SecureCRT console opened.")
                    except Exception as exc:
                        st.error(str(exc))
                st.caption(
                    "Default console launcher: SecureCRT"
                    if console_launcher == "SecureCRT Telnet"
                    else "Default console launcher: Windows telnet"
                )

            if has_value(row["Mgmt IP"]):
                ssh_user = target_oob["username"] if target_oob else ""
                st.code(
                    f"ssh {ssh_user + '@' if ssh_user else ''}{row['Mgmt IP']}",
                    language="powershell",
                )
                mssh1, mssh2 = st.columns(2)
                if mssh1.button("SSH Mgmt", use_container_width=True):
                    try:
                        launch_windows_ssh(row["Mgmt IP"], 22, ssh_user)
                        audit(
                            "launch_ssh_mgmt",
                            oob_id=row["OOBID"],
                            device_id=row["DeviceID"],
                            detail=str(row["Mgmt IP"]),
                        )
                        st.toast("Management SSH opened.")
                    except Exception as exc:
                        st.error(str(exc))
                if mssh2.button("SecureCRT SSH", use_container_width=True):
                    try:
                        launch_securecrt_ssh(row["Mgmt IP"], 22, ssh_user, securecrt_path)
                        audit(
                            "launch_securecrt_ssh",
                            oob_id=row["OOBID"],
                            device_id=row["DeviceID"],
                            detail=str(row["Mgmt IP"]),
                        )
                        st.toast("SecureCRT SSH opened.")
                    except Exception as exc:
                        st.error(str(exc))
                st.caption(
                    "Default management launcher: SecureCRT"
                    if mgmt_launcher == "SecureCRT SSH"
                    else "Default management launcher: Windows SSH"
                )

            if row["DeviceID"] is not None:
                if st.button("Edit inventory", use_container_width=True):
                    st.session_state.device_edit_id = int(row["DeviceID"])
                    st.rerun()
            elif row["Mapping"] == "UNMANAGED":
                if st.button(
                    "Add discovered device",
                    use_container_width=True,
                    type="primary",
                ):
                    st.session_state.device_edit_id = -2
                    st.session_state.prefill_discovered = row
                    st.rerun()

    edit_id = st.session_state.device_edit_id

    if edit_id is not None:
        st.divider()
        is_new = edit_id in (-1, -2)
        existing = None if is_new else get_device(int(edit_id))
        pre = st.session_state.get("prefill_discovered", {}) if edit_id == -2 else {}

        st.subheader("Add Device" if is_new else f"Edit · {existing['hostname']}")

        oob_options = {"(No OOB)": None}
        oob_options.update({x["name"]: x["id"] for x in oobs})

        current_oob_id = pre.get("OOBID") if is_new else existing.get("oob_id")
        oob_names = list(oob_options)
        default_oob_index = next(
            (i for i, name in enumerate(oob_names) if oob_options[name] == current_oob_id),
            0,
        )

        device_types = ["","BRAS","PE","Router","Switch","Firewall","Console Server","Other"]

        with st.form("device_form"):
            a,b,c = st.columns([2.2,1.2,1.6])
            with a:
                hostname = st.text_input(
                    "Hostname",
                    value=pre.get("Device","") if is_new else existing["hostname"],
                )
            with b:
                dtype_value = "" if is_new else existing["device_type"]
                dtype_index = device_types.index(dtype_value) if dtype_value in device_types else 0
                dtype = st.selectbox("Type", device_types, index=dtype_index)
            with c:
                selected_oob_name = st.selectbox(
                    "OOB",
                    oob_names,
                    index=default_oob_index,
                )

            a,b,c,d = st.columns(4)
            with a:
                vendor = st.text_input("Vendor", value="" if is_new else existing["vendor"])
            with b:
                model = st.text_input("Model", value="" if is_new else existing["model"])
            with c:
                serial = st.text_input("Serial", value="" if is_new else existing["serial"])
            with d:
                mgmt_ip = st.text_input("Management IP", value="" if is_new else existing["mgmt_ip"])

            a,b,c = st.columns(3)
            with a:
                site = st.text_input("Site", value="" if is_new else existing["site"])
            with b:
                rack = st.text_input("Rack", value="" if is_new else existing["rack"])
            with c:
                upos = st.text_input("U position", value="" if is_new else existing["u_position"])

            a,b = st.columns(2)
            with a:
                line_txt = st.text_input(
                    "Expected Console Line",
                    value=str(pre.get("Line","")) if is_new
                    else ("" if existing["expected_line"] is None else str(existing["expected_line"])),
                )
            with b:
                expected_alias = st.text_input(
                    "Expected Alias",
                    value=pre.get("Alias","") if is_new else existing["expected_alias"],
                )

            notes = st.text_area(
                "Notes",
                value="" if is_new else existing["notes"],
                height=75,
            )

            x,y,z = st.columns([1,1,4])
            save = x.form_submit_button("Save", type="primary", use_container_width=True)
            cancel = y.form_submit_button("Cancel", use_container_width=True)

        if cancel:
            st.session_state.device_edit_id = None
            st.session_state.pop("prefill_discovered", None)
            st.rerun()

        if save:
            try:
                line_val = int(line_txt) if line_txt.strip() else None
                device_id = save_device(
                    device_id=None if is_new else int(edit_id),
                    oob_id=oob_options[selected_oob_name],
                    hostname=hostname,
                    device_type=dtype,
                    vendor=vendor,
                    model=model,
                    serial=serial,
                    mgmt_ip=mgmt_ip,
                    site=site,
                    rack=rack,
                    u_position=upos,
                    expected_line=line_val,
                    expected_alias=expected_alias,
                    notes=notes,
                )
                audit(
                    "save_device",
                    oob_id=oob_options[selected_oob_name],
                    device_id=device_id,
                    detail=hostname,
                )
                st.session_state.device_edit_id = None
                st.session_state.pop("prefill_discovered", None)
                st.rerun()
            except Exception as exc:
                st.error(f"Save failed: {type(exc).__name__}: {exc}")

        if not is_new:
            confirm = st.checkbox("Confirm delete this device.")
            if st.button("Delete Device", disabled=not confirm):
                delete_device(int(edit_id))
                audit("delete_device", device_id=int(edit_id), detail=existing["hostname"])
                st.session_state.device_edit_id = None
                st.rerun()

# ==============================================================
# OOB
# ==============================================================
if active_page == "OOB Nodes":
    st.subheader("OOB Nodes")
    st.caption("IP · SSH · profile · site")

    oob_df = pd.DataFrame(oobs)

    if not oob_df.empty:
        show_cols = [
            "id","name","vendor","profile_key","host",
            "port","username","site","updated_at"
        ]
        st.dataframe(
            styled_table(oob_df[show_cols]),
            use_container_width=True,
            hide_index=True,
            height=min(430, 75 + 35 * len(oob_df)),
        )

    c1,c2 = st.columns([1,4])

    if c1.button("+ Add OOB", use_container_width=True):
        st.session_state.oob_edit_id = -1

    if oobs:
        edit_label = c2.selectbox(
            "Select OOB",
            [""] + [f"{x['id']} · {x['name']} · {x['host']}" for x in oobs],
            label_visibility="collapsed",
        )
        if edit_label and st.button("Edit selected OOB"):
            st.session_state.oob_edit_id = int(edit_label.split(" · ")[0])

    oe = st.session_state.oob_edit_id

    if oe is not None:
        existing = None if oe == -1 else get_oob(int(oe))
        st.subheader("Add OOB" if oe == -1 else f"Edit · {existing['name']}")

        profile_keys = list(profiles.keys())
        selected_profile = "cisco" if oe == -1 else existing["profile_key"]
        if selected_profile not in profile_keys:
            selected_profile = profile_keys[0]

        with st.form("oob_form"):
            a,b,c = st.columns([2,1.2,1.5])
            with a:
                name = st.text_input("OOB Name", value="" if oe == -1 else existing["name"])
            with b:
                profile_key = st.selectbox(
                    "Profile",
                    profile_keys,
                    index=profile_keys.index(selected_profile),
                )
            with c:
                site = st.text_input("Site", value="" if oe == -1 else existing["site"])

            a,b,c = st.columns([2,1,2])
            with a:
                host = st.text_input("IP / Hostname", value="" if oe == -1 else existing["host"])
            with b:
                port = st.number_input(
                    "SSH Port",
                    1,
                    65535,
                    value=22 if oe == -1 else int(existing["port"]),
                )
            with c:
                username = st.text_input(
                    "Default Username",
                    value="" if oe == -1 else existing["username"],
                )

            notes = st.text_area(
                "Notes",
                value="" if oe == -1 else existing["notes"],
                height=70,
            )

            x,y,z = st.columns([1,1,4])
            save = x.form_submit_button("Save", type="primary", use_container_width=True)
            cancel = y.form_submit_button("Cancel", use_container_width=True)

        if cancel:
            st.session_state.oob_edit_id = None
            st.rerun()

        if save:
            try:
                profile = profiles[profile_key]
                oob_id = save_oob(
                    oob_id=None if oe == -1 else int(oe),
                    name=name,
                    vendor=profile.get("vendor", profile_key),
                    profile_key=profile_key,
                    host=host,
                    port=int(port),
                    username=username,
                    site=site,
                    notes=notes,
                )
                audit("save_oob", oob_id=oob_id, detail=name)
                st.session_state.oob_edit_id = None
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

        if oe != -1:
            confirm = st.checkbox(
                "Confirm delete this OOB and related detected/snapshot/change data."
            )
            if st.button("Delete OOB", disabled=not confirm):
                delete_oob(int(oe))
                audit("delete_oob", oob_id=int(oe), detail=existing["name"])
                if live.oob_id == int(oe):
                    live.disconnect()
                st.session_state.oob_edit_id = None
                st.rerun()

# ==============================================================
# CHANGES / ALERT CENTER
# ==============================================================
if active_page == "Changes":
    st.subheader("Change & Alert Center")

    counts = count_open_events()
    c1,c2,c3,c4 = st.columns(4)
    render_kpi(c1, "Critical", counts["CRITICAL"], "red", "urgent")
    render_kpi(c2, "High", counts["HIGH"], "red" if counts["HIGH"] else "green", "mapping risk")
    render_kpi(c3, "Warning", counts["WARNING"], "amber", "review")
    render_kpi(c4, "Info", counts["INFO"], "blue", "session events")

    f1,f2,f3 = st.columns(3)
    with f1:
        status_filter = st.selectbox(
            "Alert status",
            ["OPEN","NEW","ACKNOWLEDGED","RESOLVED","ALL"],
        )
    with f2:
        severity_filter = st.selectbox(
            "Severity",
            ["ALL","CRITICAL","HIGH","WARNING","INFO"],
        )
    with f3:
        oob_names = ["ALL"] + [x["name"] for x in oobs]
        alert_oob_name = st.selectbox("OOB", oob_names, key="alert_oob_filter")

    alert_oob_id = None
    if alert_oob_name != "ALL":
        alert_oob_id = next(
            x["id"] for x in oobs if x["name"] == alert_oob_name
        )

    query_status = None if status_filter in {"ALL","OPEN"} else status_filter
    query_severity = None if severity_filter == "ALL" else severity_filter

    events = list_change_events(
        status=query_status,
        severity=query_severity,
        oob_id=alert_oob_id,
        limit=500,
    )

    if status_filter == "OPEN":
        events = [e for e in events if e["status"] != "RESOLVED"]

    events_df = pd.DataFrame(events)

    if not events_df.empty:
        chart1, chart2 = st.columns(2)
        render_bar_chart(chart1, "Severity Mix", count_rows(events_df, "severity"))
        render_bar_chart(chart2, "Alert State", count_rows(events_df, "status"))

    if events_df.empty:
        st.info("No matching events.")
    else:
        cols = [
            "id","severity","status","oob_name","line_no",
            "event_type","device_name","occurrence_count","last_seen","message"
        ]
        st.dataframe(
            styled_table(events_df[cols]),
            use_container_width=True,
            hide_index=True,
            height=min(520, 75 + 35 * len(events_df)),
        )

        event_labels = {
            f"#{e['id']} · {e['severity']} · {e['event_type']} · {e['oob_name']}": e
            for e in events
        }

        selected_event_label = st.selectbox(
            "Alert detail",
            list(event_labels.keys()),
            label_visibility="collapsed",
        )
        event = event_labels[selected_event_label]

        a,b = st.columns([2.2,1])

        with a:
            detail = pd.DataFrame([
                ["Event ID", event["id"]],
                ["Severity", event["severity"]],
                ["Status", event["status"]],
                ["OOB", event["oob_name"]],
                ["Device", event["device_name"] or "-"],
                ["Line", event["line_no"] if event["line_no"] is not None else "-"],
                ["Type", event["event_type"]],
                ["Old", event["old_value"] or "-"],
                ["New", event["new_value"] or "-"],
                ["First Seen", event["first_seen"]],
                ["Last Seen", event["last_seen"] or event["first_seen"]],
                ["Occurrences", event.get("occurrence_count", 1)],
                ["Acknowledged", event["acknowledged_at"] or "-"],
                ["Acknowledged By", event.get("acknowledged_by") or "-"],
                ["Resolved", event["resolved_at"] or "-"],
                ["Resolved By", event.get("resolved_by") or "-"],
                ["Note", event["note"] or "-"],
            ], columns=["Field","Value"])
            st.dataframe(
                detail.astype(str),
                use_container_width=True,
                hide_index=True,
                height=460,
            )
            st.warning(event["message"])

        with b:
            st.write("**Alert Action**")
            note = st.text_area(
                "Note",
                value=event["note"] or "",
                height=120,
                key=f"event_note_{event['id']}",
            )

            if event["status"] != "ACKNOWLEDGED":
                if st.button(
                    "Acknowledge",
                    use_container_width=True,
                    key=f"ack_{event['id']}",
                ):
                    update_change_event_status(
                        int(event["id"]),
                        status="ACKNOWLEDGED",
                        note=note,
                    )
                    audit(
                        "ack_alert",
                        oob_id=event["oob_id"],
                        device_id=event["device_id"],
                        detail=f"event={event['id']}",
                    )
                    st.rerun()

            if event["status"] != "RESOLVED":
                if st.button(
                    "Resolve",
                    use_container_width=True,
                    type="primary",
                    key=f"resolve_{event['id']}",
                ):
                    update_change_event_status(
                        int(event["id"]),
                        status="RESOLVED",
                        note=note,
                    )
                    audit(
                        "resolve_alert",
                        oob_id=event["oob_id"],
                        device_id=event["device_id"],
                        detail=f"event={event['id']}",
                    )
                    st.rerun()

            if event["status"] != "NEW":
                if st.button(
                    "Reopen",
                    use_container_width=True,
                    key=f"reopen_{event['id']}",
                ):
                    update_change_event_status(
                        int(event["id"]),
                        status="NEW",
                        note=note,
                    )
                    st.rerun()

# ==============================================================
# DISCOVERY
# ==============================================================
if active_page == "Discovery":
    st.subheader("Connect & Discover")
    st.caption("Short scan session · password not saved")

    if not oobs:
        st.info("Add an OOB node first.")
    else:
        by_label = {
            f"{x['name']} · {x['host']} · {x['vendor']}": x
            for x in oobs
        }
        label = st.selectbox("OOB", list(by_label))
        target = by_label[label]
        profile = load_profile(target["profile_key"])

        a,b,c = st.columns([2,2,1])
        with a:
            username = st.text_input(
                "Username", value=target["username"], key="disc_user"
            )
        with b:
            password = st.text_input(
                "Password", type="password", key="disc_pass",
                help="Not saved."
            )
        with c:
            st.write("")
            st.write("")
            connect_scan = st.button(
                "Connect & Scan", type="primary", use_container_width=True
            )

        if connect_scan:
            if not username.strip() or not password:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = "Cần username/password. Password field đã được xóa."
                st.rerun()
            try:
                with st.spinner("Đang SSH tuần tự, parse quality-check và compare snapshot..."):
                    # Lock covers BOTH SSH connect and scan. No second browser/session can
                    # open another scan connection while this one is active.
                    with global_scan_lock():
                        try:
                            live.connect(
                                oob_id=target["id"],
                                name=target["name"],
                                host=target["host"],
                                port=target["port"],
                                username=username,
                                password=password,
                                device_type=profile.get("netmiko_device_type", "cisco_ios"),
                                profile_key=target["profile_key"],
                                connect_timeout=int(profile.get("connect_timeout", 8)),
                                retries=int(profile.get("connect_retries", 2)),
                            )
                            # Remove our local plaintext reference immediately after auth.
                            password = ""
                            result = scan(
                                live, target["id"], target["profile_key"], acquire_lock=False
                            )
                            st.session_state.last_scan = result
                            st.session_state.last_scan_oob_id = target["id"]
                            audit(
                                "scan",
                                oob_id=target["id"],
                                detail=(
                                    f"accepted={result['accepted']}; rows={len(result['records'])}; "
                                    f"events={result['change_count']}; quality={result['parse_quality']:.2f}"
                                ),
                            )
                        finally:
                            # Short-lived scan session: never keep management SSH open in background.
                            live.disconnect()

                st.session_state["_clear_disc_pass"] = True
                if not result["accepted"]:
                    st.session_state["_flash_warning"] = (
                        "Scan bị quality gate từ chối. Current state/baseline KHÔNG bị ghi đè và không tạo alert. "
                        + result["parse_summary"]
                    )
                elif result["baseline_created"]:
                    st.session_state["_flash_success"] = (
                        f"Scan hợp lệ: {len(result['records'])} line/device. Baseline được tạo; "
                        f"inventory mismatch vẫn được kiểm tra."
                    )
                elif result["change_count"]:
                    st.session_state["_flash_warning"] = (
                        f"Scan hợp lệ: {len(result['records'])} line/device · "
                        f"{result['change_count']} event được tạo/cập nhật "
                        f"({result['new_event_count']} event mới)."
                    )
                else:
                    st.session_state["_flash_success"] = (
                        f"Scan hợp lệ: {len(result['records'])} line/device · không phát hiện thay đổi."
                    )
                st.rerun()

            except NetmikoAuthenticationException:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = (
                    "Authentication failed. Tool không retry sai credential để tránh account lockout."
                )
                st.rerun()
            except NetmikoTimeoutException:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = (
                    "SSH timeout sau retry hữu hạn. Kiểm tra IP/port/routing/ACL hoặc stale SSH session."
                )
                st.rerun()
            except ScanBusyError as exc:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_warning"] = str(exc)
                st.rerun()
            except Exception as exc:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = f"{type(exc).__name__}: {exc}"
                st.rerun()

        st.caption("Each scan uses one short SSH session.")

        result = st.session_state.last_scan
        if result and st.session_state.get("last_scan_oob_id") == target["id"]:
            rec_df = pd.DataFrame(result["records"])
            s1,s2,s3,s4 = st.columns(4)
            quality_tone = "green" if result["parse_quality"] >= 0.85 else "amber"
            render_kpi(s1, "Detected", len(result["records"]), "blue", "lines/devices")
            render_kpi(s2, "Parse Quality", f"{result['parse_quality']:.2f}", quality_tone, "quality gate")
            render_kpi(
                s3,
                "Mapping Trust",
                "YES" if result["mapping_confident"] else "NO",
                "green" if result["mapping_confident"] else "amber",
                "alias parser",
            )
            render_kpi(
                s4,
                "Session Trust",
                "YES" if result["session_confident"] else "NO",
                "green" if result["session_confident"] else "amber",
                "user parser",
            )

            if not result["accepted"]:
                st.error("REJECTED: không commit current state/snapshot/alerts.")
            elif result["parse_summary"] and result["parse_summary"] != "OK":
                st.warning(result["parse_summary"])

            if not rec_df.empty:
                st.dataframe(
                    styled_table(rec_df), use_container_width=True, hide_index=True,
                    height=min(500, 75 + 35 * len(rec_df)),
                )

            if result["errors"]:
                with st.expander("Command fallback / transport errors"):
                    for error in result["errors"]:
                        st.code(error, language="text")

            with st.expander("Raw discovery output"):
                for kind, item in result["raw"].items():
                    st.write(f"**{kind}** · `{item.get('command') or 'no working command'}`")
                    st.code(item.get("output", "") or "(empty)", language="text")

        if target["profile_key"] == "viettix":
            st.info(
                "Viettix mapping is disabled until the parser is verified."
            )
            with st.expander("Edit Viettix discovery profile"):
                profile_data = load_profile("viettix")
                txt = st.text_area(
                    "Profile JSON",
                    value=json.dumps(profile_data, ensure_ascii=False, indent=2),
                    height=430,
                )
                if st.button("Save Viettix Profile"):
                    try:
                        new_profile = json.loads(txt)
                        save_profile("viettix", new_profile)
                        audit("save_viettix_profile", detail="Profile updated")
                        st.success("Đã lưu profile.")
                    except Exception as exc:
                        st.error(f"JSON/profile không hợp lệ: {exc}")

# ==============================================================
# DATA
# ==============================================================
if active_page == "Data":
    st.subheader("Data Management")
    st.caption("Inventory · snapshots · alerts · audit")

    devices = list_devices()
    inv_df = pd.DataFrame(devices)

    a,b,c = st.columns(3)
    with a:
        if devices:
            csv = inv_df.to_csv(index=False).encode("utf-8-sig")
            st.download_button(
                "Export Inventory CSV", csv, "oob_inventory.csv", "text/csv",
                use_container_width=True,
            )
        else:
            st.button("Export Inventory CSV", disabled=True, use_container_width=True)
    with b:
        uploaded = st.file_uploader("Import CSV", type=["csv"], label_visibility="collapsed")
    with c:
        if st.button("Backup SQLite Now", use_container_width=True):
            path = backup_db()
            keep = int(get_setting("backup_keep_count", "30"))
            removed = prune_backups(keep)
            audit("backup_db", detail=f"backup={path.name}; pruned={removed}")
            st.success(f"Backup: {path.name}")

    if uploaded is not None:
        try:
            incoming = pd.read_csv(uploaded)
            preview = preview_inventory_import(incoming)
            st.write("**Import Preview / Diff**")
            if preview.issues:
                for issue in preview.issues:
                    st.error(issue)
            preview_df = pd.DataFrame(preview.rows)
            if not preview_df.empty:
                show_cols = [
                    "action","oob_name","hostname","device_type","expected_line",
                    "expected_alias","mgmt_ip","rack","changed_fields"
                ]
                st.dataframe(
                    styled_table(preview_df[[c for c in show_cols if c in preview_df.columns]]),
                    use_container_width=True, hide_index=True,
                )
                add_count = int((preview_df["action"] == "ADD").sum())
                update_count = int((preview_df["action"] == "UPDATE").sum())
                unchanged_count = int((preview_df["action"] == "UNCHANGED").sum())
                st.info(
                    f"ADD={add_count} · UPDATE={update_count} · UNCHANGED={unchanged_count}. Review before apply."
                )

                mode = st.radio(
                    "Import mode",
                    ["Add only (safe default)", "Apply ADD + UPDATE"],
                    horizontal=True,
                )
                reviewed = st.checkbox("Reviewed diff and confirm apply.")
                if st.button(
                    "Apply Import",
                    type="primary",
                    disabled=(not preview.valid or not reviewed),
                ):
                    result = apply_inventory_import(
                        preview.rows,
                        allow_updates=(mode == "Apply ADD + UPDATE"),
                    )
                    audit("import_inventory", detail=str(result))
                    st.success(f"Import hoàn tất: {result}")
                    st.rerun()
        except Exception as exc:
            st.error(f"Không đọc/preview được CSV: {exc}")

    st.divider()
    st.write("**Retention & Scheduled Backup**")
    r1,r2,r3 = st.columns(3)
    with r1:
        snapshot_days = st.number_input(
            "Snapshot retention (days)", min_value=7, max_value=3650,
            value=int(get_setting("snapshot_retention_days", "90")), step=1,
        )
    with r2:
        raw_days = st.number_input(
            "Raw scan retention (days)", min_value=1, max_value=3650,
            value=int(get_setting("scan_raw_retention_days", "30")), step=1,
        )
    with r3:
        backup_keep = st.number_input(
            "Keep backup files", min_value=3, max_value=365,
            value=int(get_setting("backup_keep_count", "30")), step=1,
        )

    s1,s2 = st.columns(2)
    if s1.button("Save Retention Settings", use_container_width=True):
        set_setting("snapshot_retention_days", str(int(snapshot_days)))
        set_setting("scan_raw_retention_days", str(int(raw_days)))
        set_setting("backup_keep_count", str(int(backup_keep)))
        audit("save_retention_settings", detail=f"snapshot={snapshot_days};raw={raw_days};backup={backup_keep}")
        st.success("Đã lưu. Scanner sẽ auto-prune sau mỗi accepted scan.")
    if s2.button("Prune History Now", use_container_width=True):
        result = prune_history(int(snapshot_days), int(raw_days))
        removed = prune_backups(int(backup_keep))
        audit("prune_history", detail=f"{result}; backups_removed={removed}")
        st.success(f"Prune hoàn tất: {result}, backups_removed={removed}")

    st.code(
        "setup_daily_backup.bat  -> daily backup 02:00\n"
        "remove_daily_backup_task.bat -> remove task",
        language="text",
    )

    st.divider()
    st.write("**Terminal Launchers**")
    l1,l2,l3 = st.columns([2.2,1.4,1.4])
    with l1:
        securecrt_path_input = st.text_input(
            "SecureCRT path",
            value=get_setting("securecrt_path", "SecureCRT.exe"),
        )
    with l2:
        console_launcher_input = st.selectbox(
            "Console default",
            ["Windows Telnet", "SecureCRT Telnet"],
            index=0 if get_setting("console_launcher", "Windows Telnet") == "Windows Telnet" else 1,
        )
    with l3:
        mgmt_launcher_input = st.selectbox(
            "Mgmt SSH default",
            ["Windows SSH", "SecureCRT SSH"],
            index=0 if get_setting("mgmt_launcher", "Windows SSH") == "Windows SSH" else 1,
        )
    if st.button("Save Launcher Settings", use_container_width=True):
        set_setting("securecrt_path", securecrt_path_input.strip() or "SecureCRT.exe")
        set_setting("console_launcher", console_launcher_input)
        set_setting("mgmt_launcher", mgmt_launcher_input)
        audit(
            "save_launcher_settings",
            detail=(
                f"console={console_launcher_input};mgmt={mgmt_launcher_input};"
                f"securecrt={securecrt_path_input}"
            ),
        )
        st.success("Launcher settings saved.")

    st.divider()
    st.write("**Data Summary**")
    range_options = {
        "7 days": 7,
        "14 days": 14,
        "19 days": 19,
        "21 days": 21,
        "All": None,
    }
    range_label = st.radio("History range", list(range_options), index=4, horizontal=True)
    range_days = range_options[range_label]
    summary = history_summary(range_days)
    h1,h2,h3,h4,h5 = st.columns(5)
    render_kpi(h1, "Detected Now", summary["detected"], "blue", "current table")
    render_kpi(h2, "Scans", summary["scans"], "cyan", range_label)
    render_kpi(h3, "Snapshots", summary["snapshots"], "violet", range_label)
    render_kpi(h4, "Events", summary["events"], "amber", range_label)
    render_kpi(h5, "Open Events", summary["open_events"], "red" if summary["open_events"] else "green", "all time")

    scans_df = pd.DataFrame(list_scans(100))
    issues_df = pd.DataFrame(list_scan_issues(200))
    chart1, chart2 = st.columns(2)
    render_bar_chart(
        chart1,
        "History Volume",
        [
            ("Detected", summary["detected"]),
            ("Scans", summary["scans"]),
            ("Snapshots", summary["snapshots"]),
            ("Events", summary["events"]),
        ],
    )
    render_bar_chart(
        chart2,
        "Operations Risk",
        [
            ("Open Events", summary["open_events"]),
            ("Rejected", int((scans_df["parse_status"] == "REJECTED").sum()) if "parse_status" in scans_df else 0),
            ("Warning", len(issues_df)),
        ],
    )

    st.divider()
    st.write("**Recent Scans**")
    if not scans_df.empty:
        scan_cols = [
            "id","oob_name","oob_host","started_at","finished_at","success",
            "parse_status","parse_quality","line_count","error_text"
        ]
        st.dataframe(
            styled_table(scans_df[[c for c in scan_cols if c in scans_df.columns]]),
            use_container_width=True, hide_index=True,
            height=min(380, 75 + 35 * len(scans_df)),
        )

    st.write("**Parser / Scan Issues**")
    if not issues_df.empty:
        st.dataframe(
            styled_table(issues_df[["id","scan_id","oob_name","issue_type","severity","message","created_at"]]),
            use_container_width=True, hide_index=True,
            height=min(360, 75 + 35 * len(issues_df)),
        )
    else:
        st.caption("No parser or scan issues.")

    st.write("**Snapshot History**")
    snapshot_oob = st.selectbox(
        "Snapshot OOB", ["ALL"] + [x["name"] for x in oobs], key="snapshot_oob"
    )
    snapshot_line = st.text_input(
        "Console line filter", placeholder="66", key="snapshot_line"
    )
    oob_id_filter = None
    if snapshot_oob != "ALL":
        oob_id_filter = next(x["id"] for x in oobs if x["name"] == snapshot_oob)
    line_filter = None
    if snapshot_line.strip():
        try:
            line_filter = int(snapshot_line.strip())
        except ValueError:
            st.warning("Console line must be a number.")

    snapshots = list_snapshots(
        oob_id=oob_id_filter,
        line_no=line_filter,
        days=range_days,
        limit=500,
    )
    snapshots_df = pd.DataFrame(snapshots)
    if not snapshots_df.empty:
        st.dataframe(
            styled_table(snapshots_df[[
                "id","scan_id","oob_name","line_no","alias","tcp_port",
                "state","session_user","captured_at"
            ]]),
            use_container_width=True, hide_index=True,
            height=min(430, 75 + 35 * len(snapshots_df)),
        )
    else:
        st.info("No matching snapshots.")

    st.write("**Audit Trail**")
    audit_df = pd.DataFrame(list_audit(300))
    if not audit_df.empty:
        st.dataframe(
            styled_table(audit_df[["ts","actor","source_host","source_ip","action","oob_id","device_id","detail"]]),
            use_container_width=True, hide_index=True,
            height=min(430, 75 + 35 * len(audit_df)),
        )

st.caption(
    "Hardened · local-only · scan lock · quality gate · audit · backup"
)
