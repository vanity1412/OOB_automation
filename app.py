from __future__ import annotations

import base64
import html
import json
from datetime import date, datetime, time, timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from core.connection import LiveOOB, clear_console_line
from core.database import DB_PATH, audit, backup_db, init_db, prune_backups
from core.importer import IMPORT_FIELDS, apply_inventory_import, preview_inventory_import
from core.profiles import list_profiles, load_profile
from core.repository import (
    analytics_alert_severity,
    analytics_daily_summary,
    assign_device_console_line,
    count_open_events,
    delete_device,
    delete_console_power_map,
    delete_oob,
    get_device,
    get_oob,
    get_setting,
    history_summary,
    list_audit_range,
    list_change_events,
    list_change_events_range,
    list_console_power_map,
    list_devices,
    list_oobs,
    list_scans,
    list_readiness_checks,
    list_scan_issues_range,
    list_scans_range,
    list_snapshots_range,
    list_terminal_contexts,
    operational_foundation_summary,
    prune_history,
    save_device,
    save_console_power_map,
    save_oob,
    set_setting,
    update_device_verification,
    update_change_event_status,
)
from core.scan_lock import ScanBusyError, global_scan_lock
from core.scanner import scan
from core.terminal import (
    check_tcp_reachable,
    launch_securecrt_ssh,
    launch_securecrt_telnet,
    launch_windows_ssh,
    launch_windows_telnet,
)
from core.vertiv_api import (
    VertivAPIAuthenticationError,
    VertivAPIError,
    VertivACSClient,
    preflight_vertiv_api,
    scan_vertiv_api,
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
for _secret_key in st.session_state.pop("_clear_secret_keys", []):
    if _secret_key in st.session_state:
        st.session_state[_secret_key] = ""

_flash_success = st.session_state.pop("_flash_success", None)
_flash_error = st.session_state.pop("_flash_error", None)
_flash_warning = st.session_state.pop("_flash_warning", None)

APP_ROOT = Path(__file__).resolve().parent
FPT_LOGO_PATH = APP_ROOT / "assets" / "fpt_telecom_logo.jpg"


def image_data_uri(path: Path) -> str:
    try:
        return "data:image/jpeg;base64," + base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return ""


FPT_LOGO_DATA_URI = image_data_uri(FPT_LOGO_PATH)

st.markdown("""
<style>
:root {
  --app-bg: #f7f8fa;
  --brand-watermark: url("__FPT_LOGO__");
  --surface: #ffffff;
  --surface-soft: #fafbfc;
  --surface-muted: #f1f5f9;
  --text: #111827;
  --text-soft: #334155;
  --muted: #64748b;
  --border: #e5e7eb;
  --border-strong: #cbd5e1;
  --accent: #2563eb;
  --accent-hover: #1d4ed8;
  --accent-soft: #dbeafe;
  --sidebar: #0f172a;
  --sidebar-line: rgba(148, 163, 184, .20);
  --green: #16a34a;
  --green-bg: #dcfce7;
  --amber: #d97706;
  --amber-bg: #fef3c7;
  --red: #dc2626;
  --red-bg: #fee2e2;
  --info: #0ea5e9;
  --info-bg: #e0f2fe;
  --slate: #64748b;
  --slate-bg: #f1f5f9;
}
html, body, .stApp, [class*="css"], button, input, textarea, select {
  font-family: "Inter", "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
}
.stApp {
  background: var(--app-bg);
  background-image:
    linear-gradient(rgba(247, 248, 250, .94), rgba(247, 248, 250, .94)),
    var(--brand-watermark);
  background-repeat: no-repeat;
  background-position: center, right 44px bottom 32px;
  background-size: auto, 420px auto;
  background-attachment: fixed;
  color: var(--text);
  font-size: 14.5px;
  line-height: 1.5;
}
[data-testid="stSidebar"] {
  background: var(--sidebar);
  border-right: 1px solid rgba(15, 23, 42, .9);
}
[data-testid="stSidebar"] > div { background: var(--sidebar); }
[data-testid="stSidebar"] * {
  color: #e5e7eb;
}
[data-testid="stSidebar"] [role="radiogroup"] { gap: 6px; }
[data-testid="stSidebar"] [role="radiogroup"] label {
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 9px 10px;
  margin: 3px 0;
  background: transparent;
  min-height: 40px;
  transition: background-color 150ms ease, border-color 150ms ease, color 150ms ease;
}
[data-testid="stSidebar"] [role="radiogroup"] label p {
  color: #cbd5e1;
  font-weight: 600;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child > div:first-child {
  display: none;
}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {
  background: rgba(148, 163, 184, .12);
  border-color: rgba(148, 163, 184, .18);
}
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"],
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: rgba(37, 99, 235, .24);
  border-color: rgba(59, 130, 246, .58);
  box-shadow: inset 3px 0 0 var(--accent);
}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p {
  color: #ffffff;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
  color: #cbd5e1;
}
.block-container {
  max-width: 1480px;
  padding-top: 20px;
  padding-bottom: 32px;
  position: relative;
  z-index: 1;
}
h1 {
  font-size: 2rem !important;
  font-weight: 700 !important;
  margin-bottom: 4px !important;
  color: var(--text);
  letter-spacing: 0 !important;
}
h2 {
  font-size: 1.35rem !important;
  font-weight: 650 !important;
  letter-spacing: 0 !important;
}
h3 {
  font-size: 1.05rem !important;
  font-weight: 650 !important;
  letter-spacing: 0 !important;
}
h1 a, h2 a, h3 a,
[data-testid="stMarkdownContainer"] h1 a,
[data-testid="stMarkdownContainer"] h2 a,
[data-testid="stMarkdownContainer"] h3 a {
  display: none !important;
}
p, label, [data-testid="stMarkdownContainer"], [data-testid="stCaptionContainer"] {
  line-height: 1.5;
}
[data-testid="stCaptionContainer"] {
  color: var(--muted);
  font-size: .86rem;
}
code, pre, [data-testid="stCodeBlock"] code {
  font-family: "SF Mono", "Cascadia Code", Consolas, monospace !important;
}
div[data-testid="stMetric"] {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  background: var(--surface);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .06);
}
div[data-testid="stDataFrame"] {
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: var(--surface);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .05);
}
[data-testid="stForm"] {
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 22px;
  background: rgba(255, 255, 255, .96);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .06);
}
[data-testid="stTextInput"],
[data-testid="stNumberInput"],
[data-testid="stSelectbox"],
[data-testid="stTextArea"] {
  margin-bottom: 8px;
}
[data-testid="stWidgetLabel"] + div {
  margin-top: 6px;
}
[data-testid="stTextInput"] [data-baseweb="input"],
[data-testid="stTextInput"] [data-baseweb="base-input"],
[data-testid="stNumberInput"] [data-baseweb="input"],
[data-testid="stNumberInput"] [data-baseweb="base-input"],
[data-testid="stSelectbox"] [data-baseweb="select"],
[data-testid="stTextArea"] [data-baseweb="textarea"] {
  border: 1px solid var(--border-strong) !important;
  border-radius: 8px !important;
  background: #ffffff !important;
  min-height: 40px !important;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04) !important;
  overflow: hidden;
}
[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea {
  display: block !important;
  visibility: visible !important;
  opacity: 1 !important;
  box-sizing: border-box !important;
  width: 100% !important;
  min-height: 40px !important;
  padding: 8px 12px !important;
  border: 1px solid var(--border-strong) !important;
  border-radius: 8px !important;
  background: #ffffff !important;
  color: var(--text) !important;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04) !important;
}
[data-testid="stTextInput"] input:placeholder-shown,
[data-testid="stTextInput"] input[value=""],
[data-testid="stTextArea"] textarea:placeholder-shown,
[data-testid="stTextArea"] textarea:empty {
  background: #ffffff !important;
  border-color: var(--border-strong) !important;
}
[data-baseweb="input"] > div,
[data-baseweb="select"] > div,
[data-baseweb="textarea"] textarea,
textarea {
  border: 1px solid var(--border-strong) !important;
  border-radius: 8px !important;
  background: #ffffff !important;
  min-height: 40px !important;
  box-shadow: inset 0 0 0 1px rgba(15, 23, 42, .02) !important;
  transition: border-color 150ms ease, box-shadow 150ms ease;
}
[data-baseweb="input"] input,
[data-baseweb="textarea"] textarea,
[data-baseweb="select"] [role="combobox"] {
  color: var(--text) !important;
  font-size: .92rem !important;
}
[data-baseweb="select"] svg,
[data-testid="stNumberInput"] button svg {
  color: var(--text-soft) !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] > div {
  border: 0 !important;
  box-shadow: none !important;
  min-height: 38px !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] [role="combobox"] {
  min-height: 38px !important;
  display: flex !important;
  align-items: center !important;
  padding-left: 10px !important;
}
[data-testid="stNumberInput"] button {
  border: 1px solid var(--border-strong) !important;
  background: var(--surface-soft) !important;
}
[data-testid="stNumberInput"] [data-baseweb="input"] {
  display: flex !important;
  align-items: stretch !important;
}
[data-baseweb="input"]:focus-within > div,
[data-baseweb="select"]:focus-within > div,
[data-baseweb="textarea"]:focus-within textarea,
textarea:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, .14) !important;
}
[data-testid="stTextInput"]:focus-within [data-baseweb="input"],
[data-testid="stTextInput"]:focus-within [data-baseweb="base-input"],
[data-testid="stNumberInput"]:focus-within [data-baseweb="input"],
[data-testid="stNumberInput"]:focus-within [data-baseweb="base-input"],
[data-testid="stSelectbox"]:focus-within [data-baseweb="select"],
[data-testid="stTextArea"]:focus-within [data-baseweb="textarea"] {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, .14) !important;
}
.stButton > button,
.stDownloadButton > button,
[data-testid="stFormSubmitButton"] button {
  border-radius: 8px !important;
  border: 1px solid var(--border) !important;
  min-height: 38px;
  padding: 7px 13px;
  font-weight: 600;
  letter-spacing: 0;
  background: #ffffff !important;
  color: var(--text) !important;
  box-shadow: 0 1px 2px rgba(0, 0, 0, .04);
  transition: background-color 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
}
.stButton > button:hover,
.stDownloadButton > button:hover,
[data-testid="stFormSubmitButton"] button:hover {
  border-color: var(--border-strong) !important;
  background: var(--surface-soft) !important;
}
.stButton > button[kind="primary"],
.stButton > [data-testid="stBaseButton-primary"],
.stDownloadButton > [data-testid="stBaseButton-primary"],
[data-testid="stFormSubmitButton"] button[kind="primary"],
[data-testid="stFormSubmitButton"] button[kind="primaryFormSubmit"],
[data-testid="stFormSubmitButton"] [data-testid="stBaseButton-primary"],
button[kind="primary"],
button[kind="primaryFormSubmit"],
button[data-testid*="stBaseButton-primary"] {
  background: var(--accent) !important;
  border-color: var(--accent) !important;
  color: #ffffff !important;
}
.stButton > button[kind="primary"]:hover,
.stButton > [data-testid="stBaseButton-primary"]:hover,
.stDownloadButton > [data-testid="stBaseButton-primary"]:hover,
[data-testid="stFormSubmitButton"] button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] button[kind="primaryFormSubmit"]:hover,
[data-testid="stFormSubmitButton"] [data-testid="stBaseButton-primary"]:hover,
button[kind="primary"]:hover,
button[kind="primaryFormSubmit"]:hover,
button[data-testid*="stBaseButton-primary"]:hover {
  background: var(--accent-hover) !important;
  border-color: var(--accent-hover) !important;
}
.small-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 20px;
  background: var(--surface);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .06);
}
.muted {color: var(--muted);}
.kpi-card {
  min-height: 92px;
  border: 1px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 8px;
  padding: 16px 18px;
  background: var(--surface);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .06);
}
.kpi-label {
  color: var(--muted);
  font-size: .76rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0;
}
.kpi-value {
  color: var(--text);
  font-size: 1.72rem;
  font-weight: 700;
  line-height: 1.15;
  margin-top: 6px;
}
.kpi-caption {
  color: var(--muted);
  font-size: .78rem;
  margin-top: 4px;
}
.status-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 4px 0 18px;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  border: 1px solid var(--pill-border);
  border-radius: 999px;
  min-height: 28px;
  padding: 4px 11px;
  color: var(--pill-text);
  background: var(--pill-bg);
  font-size: .82rem;
  font-weight: 650;
  line-height: 1;
  white-space: nowrap;
}
.pill-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--pill-text);
}
.section-note {
  border: 1px solid #bfdbfe;
  border-left: 4px solid var(--accent);
  border-radius: 8px;
  padding: 14px 16px;
  background: #eff6ff;
  color: #1e3a8a;
  font-size: .9rem;
}
.chart-panel {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  padding: 16px 18px 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, .05);
}
.chart-title {
  color: var(--muted);
  font-size: .78rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0;
  margin-bottom: 8px;
}
.sidebar-brand {
  padding: 10px 4px 16px;
  border-bottom: 1px solid var(--sidebar-line);
  margin-bottom: 12px;
}
.sidebar-logo-shell {
  width: 132px;
  border-radius: 8px;
  background: #ffffff;
  padding: 7px;
  margin-bottom: 12px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, .18);
}
.sidebar-logo {
  display: block;
  width: 100%;
  height: auto;
  border-radius: 5px;
}
.sidebar-brand-title {
  color: #f8fafc;
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: 0;
}
.sidebar-brand-subtitle {
  color: #94a3b8;
  font-size: .78rem;
  margin-top: 4px;
}
.sidebar-stats-card {
  border: 1px solid var(--sidebar-line);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, .04);
  margin-top: 16px;
}
.sidebar-status {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #e5e7eb;
  font-size: .86rem;
  font-weight: 650;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--sidebar-line);
}
.sidebar-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--sidebar-dot);
  box-shadow: 0 0 0 3px rgba(255, 255, 255, .06);
}
.sidebar-stat-row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  padding-top: 10px;
}
.sidebar-stat-label {
  color: #94a3b8;
  font-size: .73rem;
  font-weight: 650;
  letter-spacing: 0;
  text-transform: uppercase;
}
.sidebar-stat-value {
  color: #f8fafc;
  font-size: .96rem;
  font-weight: 700;
  text-align: right;
}
.empty-state {
  min-height: 96px;
  border: 1px dashed var(--border-strong);
  border-radius: 8px;
  background: var(--surface);
  color: var(--muted);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 20px;
  text-align: center;
  box-shadow: 0 1px 2px rgba(0, 0, 0, .03);
}
.empty-state-icon {
  width: 22px;
  height: 22px;
  border-radius: 999px;
  border: 1px solid var(--border-strong);
  background: var(--surface-muted);
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: .78rem;
  font-weight: 700;
  flex: 0 0 auto;
}
[data-testid="stAlert"] {
  border-radius: 8px;
  border: 1px solid var(--border);
  box-shadow: 0 1px 2px rgba(0, 0, 0, .03);
}
button[data-baseweb="tab"] {
  font-weight: 600;
  letter-spacing: 0;
  color: var(--muted);
}
button[data-baseweb="tab"][aria-selected="true"] {
  color: var(--accent);
}
@media(max-width:980px){
  .block-container{
    padding-left: .85rem;
    padding-right: .85rem;
  }
  [data-testid="stHorizontalBlock"] {
    flex-wrap: wrap;
  }
  [data-testid="stHorizontalBlock"] > [data-testid="column"] {
    min-width: 240px;
    flex: 1 1 240px !important;
  }
}
</style>
""".replace("__FPT_LOGO__", FPT_LOGO_DATA_URI), unsafe_allow_html=True)

TONE_THEME = {
    "blue": ("#dbeafe", "#2563eb", "#bfdbfe"),
    "green": ("#dcfce7", "#16a34a", "#bbf7d0"),
    "amber": ("#fef3c7", "#d97706", "#fde68a"),
    "red": ("#fee2e2", "#dc2626", "#fecaca"),
    "cyan": ("#e0f2fe", "#0ea5e9", "#bae6fd"),
    "slate": ("#f1f5f9", "#64748b", "#e2e8f0"),
}

VALUE_TONES = {
    "AVAILABLE": "green",
    "BUSY": "amber",
    "UNKNOWN": "slate",
    "MATCH": "green",
    "MISMATCH": "red",
    "UNMANAGED": "amber",
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
    "SNAPSHOTS": "blue",
    "EVENTS": "amber",
    "OPEN EVENTS": "red",
    "READY": "green",
    "FOUNDATION": "amber",
    "PLANNED": "slate",
    "VERIFIED": "green",
    "UNVERIFIED": "slate",
    "STALE": "red",
    "HEALTHY": "green",
    "AVAILABLE_CONFIRMED": "green",
    "ACTIVE_OPERATOR": "amber",
    "STALE_SESSION": "amber",
    "BUSY_NO_USER": "amber",
    "INCONSISTENT": "red",
    "NO_OUTPUT": "red",
    "BOOTLOADER": "amber",
    "BOOTLOADER_OR_ROMMON": "amber",
    "UNKNOWN_CONTEXT": "slate",
    "WRONG_BAUD": "red",
    "OK": "green",
    "LINE_CHANGED": "red",
    "NOT_DETECTED": "red",
    "EXPECTED_ALIAS_MISMATCH": "red",
    "ALIAS_MISSING": "amber",
    "UNVERIFIED_LINE": "amber",
    "LINE_OCCUPIED_BY_UNKNOWN": "amber",
    "NEW_CONSOLE_DEVICE": "amber",
    "CONSOLE_MAPPING_CHANGED": "red",
    "EXPECTED_DEVICE_NOT_DETECTED": "red",
    "OOB": "blue",
    "TARGET": "green",
    "LIVE DB": "green",
    "DEMO DB": "amber",
    "IP_READY": "green",
    "IP_ONLY": "amber",
    "MISSING_IP": "red",
    "UNKNOWN": "slate",
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


def render_empty_state(message: str) -> None:
    st.markdown(
        "<div class='empty-state'>"
        "<span class='empty-state-icon'>i</span>"
        f"<span>{html.escape(message)}</span>"
        "</div>",
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
            axis_values = list(range(max_count + 1)) if max_count <= 20 else None
            chart = (
                alt.Chart(frame)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                .encode(
                    x=alt.X("label:N", title=None, sort=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y(
                        "count:Q",
                        title=None,
                        scale=alt.Scale(domain=[0, max_count]),
                        axis=alt.Axis(values=axis_values, format="d"),
                    ),
                    color=alt.Color("color:N", scale=None, legend=None),
                    tooltip=[
                        alt.Tooltip("label:N", title="Type"),
                        alt.Tooltip("count:Q", title="Count"),
                    ],
                )
                .properties(height=height)
            )
            st.altair_chart(chart, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)


def render_multi_line_chart(
    container,
    title: str,
    frame: pd.DataFrame,
    x_col: str,
    y_cols: list[str],
    labels: dict[str, str],
    *,
    height: int = 220,
    y_title: str = "",
) -> None:
    with container:
        st.markdown(
            f"<div class='chart-panel'><div class='chart-title'>{html.escape(title)}</div>",
            unsafe_allow_html=True,
        )
        if frame.empty or not all(col in frame.columns for col in [x_col] + y_cols):
            st.caption("No data")
        else:
            work = frame[[x_col] + y_cols].copy()
            work[x_col] = pd.to_datetime(work[x_col], errors="coerce")
            long = work.melt(id_vars=[x_col], value_vars=y_cols, var_name="metric", value_name="value")
            long["metric"] = long["metric"].map(labels).fillna(long["metric"])
            long["value"] = pd.to_numeric(long["value"], errors="coerce").fillna(0)
            long["color"] = long["metric"].map(lambda value: tone_color(value))
            if long["value"].sum() == 0:
                st.caption("No activity in selected range")
            else:
                domain = list(dict.fromkeys(labels.values()))
                color_range = [tone_color(value) for value in domain]
                chart = (
                    alt.Chart(long)
                    .mark_line(point=True, strokeWidth=2.5)
                    .encode(
                        x=alt.X(f"{x_col}:T", title=None, axis=alt.Axis(labelAngle=0)),
                        y=alt.Y("value:Q", title=y_title or None),
                        color=alt.Color(
                            "metric:N",
                            title=None,
                            scale=alt.Scale(domain=domain, range=color_range),
                        ),
                        tooltip=[
                            alt.Tooltip(f"{x_col}:T", title="Day"),
                            alt.Tooltip("metric:N", title="Metric"),
                            alt.Tooltip("value:Q", title="Value", format=".2f"),
                        ],
                    )
                    .properties(height=height)
                )
                st.altair_chart(chart, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)


def render_stacked_bar_chart(
    container,
    title: str,
    frame: pd.DataFrame,
    x_col: str,
    y_cols: list[str],
    labels: dict[str, str],
    *,
    height: int = 220,
) -> None:
    with container:
        st.markdown(
            f"<div class='chart-panel'><div class='chart-title'>{html.escape(title)}</div>",
            unsafe_allow_html=True,
        )
        if frame.empty or not all(col in frame.columns for col in [x_col] + y_cols):
            st.caption("No data")
        else:
            work = frame[[x_col] + y_cols].copy()
            work[x_col] = pd.to_datetime(work[x_col], errors="coerce")
            long = work.melt(id_vars=[x_col], value_vars=y_cols, var_name="metric", value_name="value")
            long["metric"] = long["metric"].map(labels).fillna(long["metric"])
            long["value"] = pd.to_numeric(long["value"], errors="coerce").fillna(0)
            long["color"] = long["metric"].map(lambda value: tone_color(value))
            if long["value"].sum() == 0:
                st.caption("No activity in selected range")
            else:
                domain = list(dict.fromkeys(labels.values()))
                color_range = [tone_color(value) for value in domain]
                chart = (
                    alt.Chart(long)
                    .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
                    .encode(
                        x=alt.X(f"{x_col}:T", title=None, axis=alt.Axis(labelAngle=0)),
                        y=alt.Y("value:Q", title=None, stack="zero"),
                        color=alt.Color(
                            "metric:N",
                            title=None,
                            scale=alt.Scale(domain=domain, range=color_range),
                        ),
                        tooltip=[
                            alt.Tooltip(f"{x_col}:T", title="Day"),
                            alt.Tooltip("metric:N", title="Metric"),
                            alt.Tooltip("value:Q", title="Count", format=".0f"),
                        ],
                    )
                    .properties(height=height)
                )
                st.altair_chart(chart, width="stretch")
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


def ip_coverage_rows(frame: pd.DataFrame) -> list[tuple[str, int]]:
    if frame.empty:
        return []
    ip_series = frame["IP"] if "IP" in frame.columns else pd.Series("", index=frame.index)
    port_series = frame["TCP Port"] if "TCP Port" in frame.columns else pd.Series("", index=frame.index)
    has_ip = ip_series.apply(has_value)
    has_port = port_series.apply(has_value)
    return [
        ("IP_READY", int((has_ip & has_port).sum())),
        ("IP_ONLY", int((has_ip & ~has_port).sum())),
        ("MISSING_IP", int((~has_ip).sum())),
    ]


def active_db_label() -> tuple[str, str, str]:
    try:
        db_display = str(DB_PATH.resolve().relative_to(APP_ROOT))
    except ValueError:
        db_display = str(DB_PATH)
    is_demo = "demo" in DB_PATH.name.lower()
    return ("Demo DB" if is_demo else "Live DB", "amber" if is_demo else "green", db_display)


def cell_style(value: object) -> str:
    key = str(value or "").strip().upper()
    tone = VALUE_TONES.get(key)
    if not tone:
        return ""
    bg, text, border = TONE_THEME[tone]
    return (
        f"background-color:{bg}; color:{text}; font-weight:650; "
        f"border-color:{border};"
    )


def row_tint(row: pd.Series) -> list[str]:
    mapping = str(row.get("Mapping", "") or "").upper()
    risk = str(row.get("Risk", "") or "").upper()
    row_severity = str(row.get("Severity", "") or "").upper()
    status = str(row.get("Status", "") or "").upper()
    verification = str(row.get("Verification", "") or "").upper()
    severity = str(row.get("severity", "") or "").upper()
    action = str(row.get("action", "") or "").upper()

    bg = ""
    if (
        mapping in {"MISMATCH", "NOT DETECTED"}
        or risk in {"MISMATCH", "LINE_CHANGED", "NOT_DETECTED", "STALE_SESSION", "BOOTLOADER_OR_ROMMON"}
        or verification == "STALE"
        or row_severity in {"CRITICAL", "HIGH"}
        or severity in {"CRITICAL", "HIGH"}
    ):
        bg = "background-color:#fff5f5;"
    elif (
        mapping == "UNMANAGED"
        or risk not in {"", "OK"}
        or verification == "UNVERIFIED"
        or status == "BUSY"
        or row_severity == "WARNING"
        or severity == "WARNING"
        or action == "UPDATE"
    ):
        bg = "background-color:#fffbeb;"
    elif status == "AVAILABLE" or action == "ADD":
        bg = "background-color:#f0fdf4;"
    elif action == "UNCHANGED":
        bg = "background-color:#f8fafc;"
    return [bg for _ in row]


def styled_table(frame: pd.DataFrame):
    styled = (
        frame.style.apply(row_tint, axis=1)
        .set_properties(
            **{
                "border-bottom": "1px solid #e5e7eb",
                "border-left": "0",
                "border-right": "0",
                "font-size": "14px",
            }
        )
        .set_table_styles(
            [
                {
                    "selector": "table",
                    "props": [
                        ("border-collapse", "collapse"),
                        ("font-size", "14px"),
                    ],
                },
                {
                    "selector": "th",
                    "props": [
                        ("background-color", "#f8fafc"),
                        ("color", "#334155"),
                        ("font-weight", "650"),
                        ("border-bottom", "1px solid #e5e7eb"),
                        ("border-left", "0"),
                        ("border-right", "0"),
                    ],
                },
                {
                    "selector": "td",
                    "props": [
                        ("border-bottom", "1px solid #e5e7eb"),
                        ("border-left", "0"),
                        ("border-right", "0"),
                        ("color", "#111827"),
                    ],
                },
                {
                    "selector": "tbody tr:hover",
                    "props": [
                        ("background-color", "#f8fafc"),
                    ],
                },
            ]
        )
    )
    highlight_cols = [
        col
        for col in (
            "Status", "Mapping", "Verification", "Risk", "Severity",
            "severity", "status", "state", "parse_status", "action",
        )
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


def console_telnet_command(row: dict[str, object] | pd.Series) -> str:
    console_ip = row.get("IP") or row.get("OOB Host")
    if has_value(row.get("TCP Port")) and has_value(console_ip):
        return f"telnet {console_ip} {as_port(row['TCP Port'])}"
    return ""


def clear_line_command(row: dict[str, object] | pd.Series) -> str:
    if has_value(row.get("Line")):
        return f"clear line {int(float(str(row['Line']).strip()))}"
    return ""


def display_ip(row: dict[str, object] | pd.Series) -> str:
    for col in ("Target", "IP", "Mgmt IP", "OOB Host"):
        value = row.get(col)
        if has_value(value):
            return str(value).strip()
    return ""


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3, "": 9}
RISKY_HEALTH = {
    "STALE_SESSION": ("HIGH", "Line looks stale across scans; verify before using console."),
    "BOOTLOADER_OR_ROMMON": ("HIGH", "Console output looks like bootloader/ROMMON context."),
    "INCONSISTENT": ("HIGH", "Line state and parsed session user conflict."),
    "NO_OUTPUT": ("WARNING", "No output was captured for this line."),
    "BUSY_NO_USER": ("WARNING", "Line is busy but no session user was parsed."),
    "UNKNOWN_CONTEXT": ("WARNING", "Console context is unknown; verify line before trusting it."),
}
RISKY_MAPPING = {
    "MISMATCH": ("HIGH", "Detected alias does not match expected inventory."),
    "NOT DETECTED": ("HIGH", "Expected inventory line/device was not detected."),
    "UNMANAGED": ("WARNING", "Detected console line has no managed inventory mapping."),
    "NO LINE": ("WARNING", "Inventory device has no expected console line."),
}
EVENT_RISK_ALIAS = {
    "DEVICE_CONSOLE_LINE_CHANGED": "LINE_CHANGED",
    "EXPECTED_DEVICE_NOT_DETECTED": "NOT_DETECTED",
}


def _safe_int(value: object) -> int | None:
    if not has_value(value):
        return None
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return None


def _event_sort_key(event: dict[str, object]) -> tuple[int, str]:
    severity = str(event.get("severity") or "").upper()
    return (SEVERITY_ORDER.get(severity, 9), str(event.get("last_seen") or ""))


def build_event_indexes(events: list[dict[str, object]]):
    by_line: dict[tuple[int, int], list[dict[str, object]]] = {}
    by_device: dict[int, list[dict[str, object]]] = {}
    for event in events:
        if str(event.get("status") or "").upper() == "RESOLVED":
            continue
        oob_id = _safe_int(event.get("oob_id"))
        line_no = _safe_int(event.get("line_no"))
        device_id = _safe_int(event.get("device_id"))
        if oob_id is not None and line_no is not None:
            by_line.setdefault((oob_id, line_no), []).append(event)
        if device_id is not None:
            by_device.setdefault(device_id, []).append(event)
    return by_line, by_device


def row_risk(
    row: dict[str, object] | pd.Series,
    events_by_line: dict[tuple[int, int], list[dict[str, object]]],
    events_by_device: dict[int, list[dict[str, object]]],
) -> tuple[str, str, str]:
    oob_id = _safe_int(row.get("OOBID"))
    line_no = _safe_int(row.get("Line"))
    device_id = _safe_int(row.get("DeviceID"))

    events: list[dict[str, object]] = []
    if oob_id is not None and line_no is not None:
        events.extend(events_by_line.get((oob_id, line_no), []))
    if device_id is not None:
        events.extend(events_by_device.get(device_id, []))
    if events:
        event = sorted(events, key=_event_sort_key)[0]
        event_type = str(event.get("event_type") or "").upper()
        risk = EVENT_RISK_ALIAS.get(event_type, event_type)
        severity = str(event.get("severity") or "").upper()
        issue = str(event.get("message") or "").strip()
        return risk or "ALERT", severity, issue

    health = str(row.get("Health") or "").upper()
    if health in RISKY_HEALTH:
        severity, issue = RISKY_HEALTH[health]
        return health, severity, str(row.get("Health Reason") or issue)

    mapping = str(row.get("Mapping") or "").upper()
    if mapping in RISKY_MAPPING:
        severity, issue = RISKY_MAPPING[mapping]
        return mapping.replace(" ", "_"), severity, issue

    verification = str(row.get("Verification") or "").upper()
    if device_id is not None and verification != "VERIFIED":
        return (
            "UNVERIFIED_LINE",
            "WARNING",
            "Line/device identity has not been verified with operator evidence.",
        )

    return "OK", "", "No active troubleshooting risk detected."


DEVICE_COLUMN_CONFIG = {
    "OOB": st.column_config.TextColumn("OOB", width="small"),
    "Line": st.column_config.NumberColumn("Line", width="small"),
    "Device": st.column_config.TextColumn("Device", width="medium"),
    "Type": st.column_config.TextColumn("Type", width="small"),
    "IP": st.column_config.TextColumn("IP", width="small"),
    "Alias": st.column_config.TextColumn("Alias", width="medium"),
    "TCP Port": st.column_config.NumberColumn("TCP Port", width="small"),
    "Status": st.column_config.TextColumn("Status", width="small"),
    "Session": st.column_config.TextColumn("Session", width="small"),
    "Health": st.column_config.TextColumn("Health", width="small"),
    "Mapping": st.column_config.TextColumn("Mapping", width="medium"),
    "Risk": st.column_config.TextColumn("Risk", width="medium"),
    "Severity": st.column_config.TextColumn("Severity", width="small"),
    "Verification": st.column_config.TextColumn("Verification", width="medium"),
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
if "power_map_edit_id" not in st.session_state:
    st.session_state.power_map_edit_id = None

live: LiveOOB = st.session_state.live
profiles = list_profiles()
oobs = list_oobs()
db_label, db_tone, db_display = active_db_label()
latest_scans = list_scans(limit=1)
latest_scan = latest_scans[0] if latest_scans else None

header_alerts = count_open_events()
header_open_alerts = sum(header_alerts.values())

nav_items = {
    "▦  Devices": "Devices",
    "▣  OOB Nodes": "OOB Nodes",
    "⚠  Changes": "Changes",
    "↻  Discovery": "Discovery",
    "▤  Data": "Data",
    "⚙  Settings": "Settings",
}

with st.sidebar:
    st.markdown(
        "<div class='sidebar-brand'>"
        "<div class='sidebar-logo-shell'><img class='sidebar-logo' src='{logo}' alt='FPT Telecom logo'></div>"
        "<div class='sidebar-brand-title'>OOB Manager</div>"
        "<div class='sidebar-brand-subtitle'>NOC operations dashboard</div>"
        "</div>".format(logo=FPT_LOGO_DATA_URI),
        unsafe_allow_html=True,
    )
    selected_nav = st.radio(
        "Navigation",
        list(nav_items.keys()),
        label_visibility="collapsed",
        key="main_nav",
    )
    active_page = nav_items[selected_nav]
    live_label = f"Connected: {live.name}" if live.connected else "Disconnected"
    live_dot = "#16a34a" if live.connected else "#64748b"
    alert_style = "color:#dc2626;" if header_open_alerts else "color:#16a34a;"
    db_style = "color:#d97706;" if db_label == "Demo DB" else "color:#16a34a;"
    last_scan_label = (
        f"{latest_scan['parse_status']} · {latest_scan['line_count']} lines"
        if latest_scan else "No scan yet"
    )
    st.markdown(
        "<div class='sidebar-stats-card'>"
        "<div class='sidebar-status' style='--sidebar-dot:{live_dot};'>"
        "<span class='sidebar-dot'></span><span>{live_label}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Data</span>"
        "<span class='sidebar-stat-value' style='{db_style}'>{db_label}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>OOB Nodes</span>"
        "<span class='sidebar-stat-value'>{oob_count}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Open Alerts</span>"
        "<span class='sidebar-stat-value' style='{alert_style}'>{alert_count}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Last Scan</span>"
        "<span class='sidebar-stat-value'>{last_scan_label}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Scan Mode</span>"
        "<span class='sidebar-stat-value'>Serial lock</span></div>"
        "</div>".format(
            live_dot=live_dot,
            live_label=html.escape(live_label),
            db_label=html.escape(db_label),
            db_style=db_style,
            oob_count=len(oobs),
            alert_count=header_open_alerts,
            alert_style=alert_style,
            last_scan_label=html.escape(last_scan_label),
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
        if st.button("Disconnect", width="stretch"):
            audit("disconnect", oob_id=live.oob_id, detail=live.host)
            live.disconnect()
            st.rerun()

render_status_strip(
    [
        ("Local GUI", "blue"),
        (f"{db_label} · {db_display}", db_tone),
        (
            f"{len(oobs)} OOB node" + ("" if len(oobs) == 1 else "s"),
            "blue" if oobs else "slate",
        ),
        (
            f"{header_open_alerts} open alert" + ("" if header_open_alerts == 1 else "s"),
            "red" if header_open_alerts else "green",
        ),
        ("Scan lock", "slate"),
        ("No saved passwords", "slate"),
    ]
)

if db_label == "Demo DB":
    st.warning(
        "Đang mở database demo. Scan thiết bị thật sẽ không hiện đúng ở màn này nếu server vẫn chạy với demo DB. "
        "Hãy mở app bằng Live DB để dùng dữ liệu production."
    )

# ==============================================================
# DEVICES
# ==============================================================
if active_page == "Devices":
    rows = build_rows()
    df = pd.DataFrame(rows)
    if not df.empty:
        df["IP"] = df.apply(display_ip, axis=1)
        events_by_line, events_by_device = build_event_indexes(list_change_events(limit=1000))
        risk_values = df.apply(
            lambda item: row_risk(item, events_by_line, events_by_device),
            axis=1,
        )
        df["Risk"] = [item[0] for item in risk_values]
        df["Severity"] = [item[1] for item in risk_values]
        df["Issue"] = [item[2] for item in risk_values]
    alert_counts = count_open_events()

    total = len(df) if not df.empty else 0
    available = int((df["Status"] == "AVAILABLE").sum()) if not df.empty else 0
    busy = int((df["Status"] == "BUSY").sum()) if not df.empty else 0
    mismatch = int((df["Mapping"] == "MISMATCH").sum()) if not df.empty else 0
    health_attention = int(df["Health"].isin(["STALE_SESSION", "BUSY_NO_USER", "INCONSISTENT", "NO_OUTPUT", "BOOTLOADER_OR_ROMMON", "UNKNOWN_CONTEXT"]).sum()) if not df.empty else 0
    risk_attention = int((df["Risk"] != "OK").sum()) if not df.empty else 0
    open_alerts = sum(alert_counts.values())

    m1,m2,m3,m4,m5,m6 = st.columns(6)
    render_kpi(m1, "Devices / Lines", total, "blue", "inventory + detected")
    render_kpi(m2, "Available", available, "green", "ready console")
    render_kpi(m3, "Busy", busy, "amber", "active sessions")
    render_kpi(m4, "Mismatch", mismatch, "red" if mismatch else "green", "mapping drift")
    render_kpi(m5, "Risk Review", risk_attention, "amber" if risk_attention else "green", "troubleshooting")
    render_kpi(m6, "Open Alerts", open_alerts, "red" if open_alerts else "green", "needs attention")

    chart1, chart2 = st.columns(2)
    render_bar_chart(chart1, "Console Status", count_rows(df, "Status"))
    render_bar_chart(chart2, "Troubleshooting Risk", count_rows(df, "Risk"))
    chart3, chart4 = st.columns(2)
    render_bar_chart(chart3, "Session Health", count_rows(df, "Health"))
    render_bar_chart(chart4, "IP / Telnet Coverage", ip_coverage_rows(df))

    st.write("**Quick Hostname Lookup**")
    hostname_lookup = st.text_input(
        "Hostname lookup",
        placeholder="Type hostname to find OOB, line, alias, status, and IP...",
        label_visibility="collapsed",
        key="hostname_lookup",
    )
    if hostname_lookup.strip():
        if df.empty:
            render_empty_state("No inventory or detected console data yet.")
        else:
            lookup_needle = hostname_lookup.strip().lower()
            lookup_mask = pd.Series(False, index=df.index)
            for col in ["Device", "Verified Hostname", "Alias", "IP", "Mgmt IP", "Serial"]:
                lookup_mask |= (
                    df[col]
                    .fillna("")
                    .astype(str)
                    .str.lower()
                    .str.contains(lookup_needle, regex=False)
                )
            lookup_df = df[lookup_mask].copy()
            if lookup_df.empty:
                st.warning("No hostname match found.")
            else:
                exact_mask = pd.Series(False, index=lookup_df.index)
                for col in ["Device", "Verified Hostname", "Alias"]:
                    exact_mask |= (
                        lookup_df[col]
                        .fillna("")
                        .astype(str)
                        .str.lower()
                        .eq(lookup_needle)
                    )
                lookup_df["_Exact"] = exact_mask.astype(int)
                lookup_df = lookup_df.sort_values(
                    by=["_Exact", "OOB", "Line"],
                    ascending=[False, True, True],
                )
                lookup_cols = [
                    "OOB", "Line", "Device", "IP", "Alias", "TCP Port",
                    "Status", "Health", "Risk", "Mapping",
                    "Verification", "Last Seen",
                ]
                st.dataframe(
                    styled_table(lookup_df[lookup_cols]),
                    width="stretch",
                    hide_index=True,
                    column_config=DEVICE_COLUMN_CONFIG,
                    height=min(260, 75 + len(lookup_df) * 35),
                )

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
            [
                "All","AVAILABLE","BUSY","UNKNOWN","MISMATCH","UNMANAGED","NOT DETECTED","NO LINE",
                "ACTIVE_OPERATOR","STALE_SESSION","BUSY_NO_USER","INCONSISTENT","NO_OUTPUT",
                "BOOTLOADER_OR_ROMMON","UNKNOWN_CONTEXT","RISK",
            ],
            label_visibility="collapsed",
        )
    with b3:
        oob_filter = st.selectbox(
            "OOB filter",
            ["All"] + [x["name"] for x in oobs],
            label_visibility="collapsed",
        )
    with b4:
        if st.button("+ Device", type="primary", width="stretch"):
            st.session_state.device_edit_id = -1

    shown = df.copy()

    if not shown.empty:
        if q.strip():
            needle = q.strip().lower()
            cols = ["Device","Alias","Line","IP","Mgmt IP","Serial","Rack","Site","Type","OOB"]
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
            elif filt in {"ACTIVE_OPERATOR","STALE_SESSION","BUSY_NO_USER","INCONSISTENT","NO_OUTPUT","BOOTLOADER_OR_ROMMON","UNKNOWN_CONTEXT"}:
                shown = shown[shown["Health"] == filt]
            elif filt == "RISK":
                shown = shown[shown["Risk"] != "OK"]
            else:
                shown = shown[shown["Status"] == filt]

        if oob_filter != "All":
            shown = shown[shown["OOB"] == oob_filter]

    table_cols = [
        "Device","IP","Line","TCP Port","Status","Health","Risk","OOB"
    ]

    if shown.empty:
        render_empty_state("No data. Add OOB, then Connect & Scan.")
    else:
        st.caption("Click một dòng để xem chi tiết; thao tác kết nối nằm ở panel bên phải hoặc ngay bên dưới trên màn hẹp.")
        table_event = st.dataframe(
            styled_table(shown[table_cols]),
            width="stretch",
            hide_index=True,
            column_config=DEVICE_COLUMN_CONFIG,
            height=min(460, 72 + len(shown) * 35),
            on_select="rerun",
            selection_mode="single-row",
            key="devices_console_table",
        )
        selected_table_row = None
        table_selection = getattr(table_event, "selection", {})
        if isinstance(table_selection, dict):
            selected_positions = table_selection.get("rows", [])
        else:
            selected_positions = getattr(table_selection, "rows", [])
        if selected_positions:
            selected_pos = int(selected_positions[0])
            if 0 <= selected_pos < len(shown):
                selected_table_row = shown.iloc[selected_pos].to_dict()

        labels = {
            f"{r['Device']} · {r['OOB']} · Line {r['Line'] if pd.notna(r['Line']) else '-'}": r
            for r in shown.to_dict("records")
        }
        selected_detail_label = None
        if selected_table_row:
            selected_detail_label = (
                f"{selected_table_row['Device']} · {selected_table_row['OOB']} · "
                f"Line {selected_table_row['Line'] if pd.notna(selected_table_row['Line']) else '-'}"
            )
        label_list = list(labels.keys())
        default_detail_index = (
            label_list.index(selected_detail_label)
            if selected_detail_label in labels else 0
        )
        selected_label = st.selectbox(
            "Device detail",
            label_list,
            index=default_detail_index,
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
                ["Session Health", row.get("Health", "-") or "-"],
                ["Health Reason", row.get("Health Reason", "-") or "-"],
                ["Prompt Context", row.get("Prompt Context", "-") or "-"],
                ["Mapping", row["Mapping"]],
                ["Risk", row.get("Risk", "OK") or "OK"],
                ["Severity", row.get("Severity", "-") or "-"],
                ["Issue", row.get("Issue", "-") or "-"],
                ["IP", row["IP"] or "-"],
                ["Inventory Mgmt IP", row["Mgmt IP"] or "-"],
                ["Vendor/Model", f"{row['Vendor']} {row['Model']}".strip() or "-"],
                ["Serial", row["Serial"] or "-"],
                ["Verification", row.get("Verification", "-") or "-"],
                ["Verification Ticket", row.get("Verification Ticket", "-") or "-"],
                ["Verification Confidence", row.get("Verification Confidence", "-")],
                ["Verified Hostname", row.get("Verified Hostname", "-") or "-"],
                ["Verified Serial", row.get("Verified Serial", "-") or "-"],
                ["Inventory Source", row.get("Source", "-") or "-"],
                ["Last Seen", row["Last Seen"] or "-"],
            ], columns=["Field","Value"])
            st.dataframe(
                detail.astype(str),
                width="stretch",
                hide_index=True,
                height=460,
            )
            with st.expander("Troubleshooting runbook"):
                selected_line = (
                    int(float(str(row["Line"]).strip()))
                    if has_value(row.get("Line")) else None
                )
                st.write("OOB checks")
                oob_cmds = []
                if selected_line is not None:
                    oob_cmds.extend([
                        f"show line {selected_line}",
                        f"show users | include {selected_line}",
                    ])
                oob_cmds.extend([
                    "show running-config | include ^menu",
                    "show running-config | include ^ip host",
                ])
                st.code("\n".join(oob_cmds), language="text")
                if console_telnet_command(row):
                    st.write("Console connect")
                    st.code(console_telnet_command(row), language="powershell")
                st.write("Read-only commands after console login")
                st.code(
                    "\n".join([
                        "terminal length 0",
                        "show version",
                        "show inventory",
                        "show logging | last 50",
                    ]),
                    language="text",
                )
                if selected_line is not None:
                    st.write("Impact command, use only with confirmation")
                    st.code(clear_line_command(row), language="text")

        with c2:
            st.write("**Actions**")

            risk = str(row.get("Risk") or "OK").upper()
            severity = str(row.get("Severity") or "").upper()
            issue = str(row.get("Issue") or "").strip()
            if risk != "OK":
                risk_text = f"{risk}" + (f" · {severity}" if severity else "")
                if severity in {"CRITICAL", "HIGH"}:
                    st.error(risk_text)
                else:
                    st.warning(risk_text)
                if issue:
                    st.caption(issue)
            else:
                st.success("Risk OK")

            if row["Status"] == "BUSY":
                st.warning(f"Console line đang BUSY · {row['Session'] or 'unknown user'}")
            elif row["Status"] == "AVAILABLE":
                st.success("Console line available.")
            else:
                st.info(f"Console state: {row['Status']}")

            if row.get("Health") in {"STALE_SESSION", "BUSY_NO_USER", "INCONSISTENT", "NO_OUTPUT", "BOOTLOADER_OR_ROMMON", "UNKNOWN_CONTEXT"}:
                st.warning(row.get("Health Reason") or f"Session health: {row.get('Health')}")

            if row["Alias"]:
                st.code(str(row["Alias"]), language="text")
                st.caption("Login alias")

            target_oob = next((x for x in oobs if x["id"] == row["OOBID"]), None)
            securecrt_path = get_setting("securecrt_path", "SecureCRT.exe")
            console_launcher = get_setting("console_launcher", "Windows Telnet")
            mgmt_launcher = get_setting("mgmt_launcher", "Windows SSH")
            if target_oob:
                if st.button("Open OOB SSH", width="stretch"):
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

            console_ip = row.get("IP") or row.get("OOB Host")
            if has_value(row["TCP Port"]) and has_value(console_ip):
                tcp_port = as_port(row["TCP Port"])
                row_line_no = int(float(str(row["Line"]).strip())) if has_value(row["Line"]) else None
                console_error_key = f"{row['OOBID']}|{row_line_no}|{tcp_port}"
                st.code(
                    console_telnet_command(row),
                    language="powershell",
                )
                console_uses_securecrt = console_launcher == "SecureCRT Telnet"
                console_label = (
                    "Open Console (SecureCRT)"
                    if console_uses_securecrt
                    else "Open Console (Telnet)"
                )
                if st.button(console_label, width="stretch", type="primary"):
                    try:
                        check_tcp_reachable(console_ip, tcp_port)
                        if console_uses_securecrt:
                            launch_securecrt_telnet(console_ip, tcp_port, securecrt_path)
                            audit(
                                "launch_securecrt_console",
                                oob_id=row["OOBID"],
                                device_id=row["DeviceID"],
                                detail=f"{row['Device']}:{tcp_port}",
                            )
                            st.toast("SecureCRT console opened.")
                        else:
                            launch_windows_telnet(console_ip, tcp_port)
                            audit(
                                "launch_telnet_console",
                                oob_id=row["OOBID"],
                                device_id=row["DeviceID"],
                                detail=f"{row['Device']}:{tcp_port}",
                            )
                            st.toast("Console telnet opened.")
                    except Exception as exc:
                        st.session_state["_console_last_error_key"] = console_error_key
                        st.error(str(exc))
                with st.expander("Other console launcher"):
                    if console_uses_securecrt:
                        if st.button("Open with Windows Telnet", width="stretch"):
                            try:
                                check_tcp_reachable(console_ip, tcp_port)
                                launch_windows_telnet(console_ip, tcp_port)
                                audit(
                                    "launch_telnet_console",
                                    oob_id=row["OOBID"],
                                    device_id=row["DeviceID"],
                                    detail=f"{row['Device']}:{tcp_port}",
                                )
                                st.toast("Console telnet opened.")
                            except Exception as exc:
                                st.session_state["_console_last_error_key"] = console_error_key
                                st.error(str(exc))
                    else:
                        if st.button("Open with SecureCRT", width="stretch"):
                            try:
                                check_tcp_reachable(console_ip, tcp_port)
                                launch_securecrt_telnet(console_ip, tcp_port, securecrt_path)
                                audit(
                                    "launch_securecrt_console",
                                    oob_id=row["OOBID"],
                                    device_id=row["DeviceID"],
                                    detail=f"{row['Device']}:{tcp_port}",
                                )
                                st.toast("SecureCRT console opened.")
                            except Exception as exc:
                                st.session_state["_console_last_error_key"] = console_error_key
                                st.error(str(exc))

                if target_oob and row_line_no is not None:
                    with st.expander(
                        "Clear line rồi connect lại",
                        expanded=st.session_state.get("_console_last_error_key") == console_error_key,
                    ):
                        st.code(clear_line_command(row), language="text")
                        active_clear_session = (
                            live.connected
                            and live.oob_id is not None
                            and int(live.oob_id) == int(row["OOBID"])
                        )
                        if active_clear_session:
                            if st.button(
                                f"Clear line {row_line_no} bằng session đang kết nối",
                                width="stretch",
                                type="primary",
                                key=f"clear_connected_{row['OOBID']}_{row_line_no}",
                            ):
                                try:
                                    target_profile = load_profile(str(target_oob.get("profile_key") or "cisco"))
                                    with st.spinner(f"Đang clear line {row_line_no} trên session active..."):
                                        clear_output = live.clear_line(
                                            row_line_no,
                                            timeout=int(target_profile.get("command_timeout", 15)),
                                        )
                                    check_tcp_reachable(console_ip, tcp_port, attempts=4, delay=1.0)
                                    if console_uses_securecrt:
                                        launch_securecrt_telnet(console_ip, tcp_port, securecrt_path)
                                    else:
                                        launch_windows_telnet(console_ip, tcp_port)
                                    audit(
                                        "clear_line_connected_then_console",
                                        oob_id=row["OOBID"],
                                        device_id=row["DeviceID"],
                                        detail=(
                                            f"line={row_line_no};device={row['Device']};"
                                            f"tcp={tcp_port};output={str(clear_output)[:200]}"
                                        ),
                                    )
                                    st.session_state.pop("_console_last_error_key", None)
                                    st.session_state["_flash_success"] = (
                                        f"Đã clear line {row_line_no} bằng session active và mở console."
                                    )
                                    st.rerun()
                                except Exception as exc:
                                    st.session_state["_console_last_error_key"] = console_error_key
                                    st.session_state["_flash_error"] = (
                                        f"Clear line failed: {type(exc).__name__}: {exc}"
                                    )
                                    st.rerun()
                            st.caption("Đang dùng session OOB active trong app; không cần nhập lại password.")
                        else:
                            st.info(
                                "Muốn clear line một phát thì vào Discovery, tick "
                                "'Keep OOB session active for clear-line actions' rồi scan OOB CLI."
                            )
                        clear_user_key = f"clear_line_user_{row['OOBID']}_{row_line_no}"
                        clear_pass_key = f"clear_line_pass_{row['OOBID']}_{row_line_no}"
                        clear_confirm_key = f"clear_line_confirm_{row['OOBID']}_{row_line_no}"
                        clear_user = st.text_input(
                            "OOB Username",
                            value=target_oob["username"],
                            key=clear_user_key,
                        )
                        clear_pass = st.text_input(
                            "OOB Password",
                            type="password",
                            key=clear_pass_key,
                            help="Dùng một lần để SSH vào OOB chạy clear line; không lưu database.",
                        )
                        clear_confirm = st.checkbox(
                            f"Confirm clear line {row_line_no}",
                            key=clear_confirm_key,
                        )
                        if st.button(
                            "Clear line rồi mở console",
                            width="stretch",
                            disabled=not clear_confirm,
                            key=f"clear_then_connect_{row['OOBID']}_{row_line_no}",
                        ):
                            try:
                                target_profile = load_profile(str(target_oob.get("profile_key") or "cisco"))
                                with st.spinner(f"Đang clear line {row_line_no} trên {target_oob['name']}..."):
                                    clear_output = clear_console_line(
                                        host=target_oob["host"],
                                        port=int(target_oob["port"]),
                                        username=clear_user,
                                        password=clear_pass,
                                        device_type=target_profile.get("netmiko_device_type", "cisco_ios"),
                                        line_no=row_line_no,
                                        connect_timeout=int(target_profile.get("connect_timeout", 8)),
                                        command_timeout=int(target_profile.get("command_timeout", 15)),
                                    )
                                check_tcp_reachable(console_ip, tcp_port, attempts=4, delay=1.0)
                                if console_uses_securecrt:
                                    launch_securecrt_telnet(console_ip, tcp_port, securecrt_path)
                                else:
                                    launch_windows_telnet(console_ip, tcp_port)
                                audit(
                                    "clear_line_then_console",
                                    oob_id=row["OOBID"],
                                    device_id=row["DeviceID"],
                                    detail=(
                                        f"line={row_line_no};device={row['Device']};"
                                        f"tcp={tcp_port};output={str(clear_output)[:200]}"
                                    ),
                                )
                                st.session_state.pop("_console_last_error_key", None)
                                st.session_state["_clear_secret_keys"] = [clear_pass_key]
                                st.session_state["_flash_success"] = (
                                    f"Đã clear line {row_line_no} và mở console telnet {console_ip}:{tcp_port}."
                                )
                                st.rerun()
                            except NetmikoAuthenticationException:
                                st.session_state["_clear_secret_keys"] = [clear_pass_key]
                                st.session_state["_flash_error"] = (
                                    "Clear line failed: sai username/password hoặc user không đủ quyền."
                                )
                                st.rerun()
                            except NetmikoTimeoutException:
                                st.session_state["_clear_secret_keys"] = [clear_pass_key]
                                st.session_state["_flash_error"] = (
                                    "Clear line failed: SSH timeout tới OOB. Kiểm tra IP/port/routing/ACL."
                                )
                                st.rerun()
                            except Exception as exc:
                                st.session_state["_console_last_error_key"] = console_error_key
                                st.session_state["_clear_secret_keys"] = [clear_pass_key]
                                st.session_state["_flash_error"] = (
                                    f"Clear line failed: {type(exc).__name__}: {exc}"
                                )
                                st.rerun()

            if has_value(row["Mgmt IP"]):
                ssh_user = target_oob["username"] if target_oob else ""
                st.code(
                    f"ssh {ssh_user + '@' if ssh_user else ''}{row['Mgmt IP']}",
                    language="powershell",
                )
                mgmt_uses_securecrt = mgmt_launcher == "SecureCRT SSH"
                mgmt_label = (
                    "Open Mgmt SSH (SecureCRT)"
                    if mgmt_uses_securecrt
                    else "Open Mgmt SSH"
                )
                if st.button(mgmt_label, width="stretch", type="primary"):
                    try:
                        if mgmt_uses_securecrt:
                            launch_securecrt_ssh(row["Mgmt IP"], 22, ssh_user, securecrt_path)
                            audit(
                                "launch_securecrt_ssh",
                                oob_id=row["OOBID"],
                                device_id=row["DeviceID"],
                                detail=str(row["Mgmt IP"]),
                            )
                            st.toast("SecureCRT SSH opened.")
                        else:
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
                with st.expander("Other management launcher"):
                    if mgmt_uses_securecrt:
                        if st.button("Open with Windows SSH", width="stretch"):
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
                    else:
                        if st.button("Open with SecureCRT SSH", width="stretch"):
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

            if row["DeviceID"] is not None:
                with st.expander("Line verification"):
                    verify_ticket = st.text_input(
                        "Ticket / change ref",
                        value=row.get("Verification Ticket", ""),
                        key=f"verify_ticket_{int(row['DeviceID'])}",
                    )
                    verify_confidence = st.slider(
                        "Confidence",
                        min_value=0.0,
                        max_value=1.0,
                        value=float(row.get("Verification Confidence", 0) or 0),
                        step=0.05,
                        key=f"verify_confidence_{int(row['DeviceID'])}",
                    )
                    verify_note = st.text_area(
                        "Verification note",
                        value="",
                        height=80,
                        key=f"verify_note_{int(row['DeviceID'])}",
                    )
                    v1,v2,v3 = st.columns(3)
                    if v1.button("Mark verified", width="stretch", type="primary", key=f"verify_ok_{int(row['DeviceID'])}"):
                        try:
                            default_note = (
                                f"OOB={row['OOB']}; line={row['Line']}; "
                                f"alias={row['Alias'] or '-'}; health={row.get('Health', 'UNKNOWN')}"
                            )
                            update_device_verification(
                                device_id=int(row["DeviceID"]),
                                status="VERIFIED",
                                source="operator_line_check",
                                verified_hostname=str(row["Device"]),
                                verified_serial=row.get("Verified Serial", ""),
                                verified_model=row.get("Verified Model", ""),
                                ticket_ref=verify_ticket,
                                confidence=verify_confidence,
                                note=verify_note.strip() or default_note,
                            )
                            audit(
                                "verify_device_line",
                                oob_id=row["OOBID"],
                                device_id=int(row["DeviceID"]),
                                detail=verify_note.strip() or default_note,
                                ticket_ref=verify_ticket,
                                note=verify_note.strip() or default_note,
                            )
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
                    if v2.button("Mark stale", width="stretch", key=f"verify_stale_{int(row['DeviceID'])}"):
                        try:
                            default_note = (
                                f"Marked stale from Devices view; OOB={row['OOB']}; line={row['Line']}."
                            )
                            update_device_verification(
                                device_id=int(row["DeviceID"]),
                                status="STALE",
                                source="operator_review",
                                ticket_ref=verify_ticket,
                                confidence=verify_confidence,
                                note=verify_note.strip() or default_note,
                            )
                            audit(
                                "mark_device_stale",
                                oob_id=row["OOBID"],
                                device_id=int(row["DeviceID"]),
                                detail=verify_note.strip() or default_note,
                                ticket_ref=verify_ticket,
                                note=verify_note.strip() or default_note,
                            )
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
                    if v3.button("Add note", width="stretch", key=f"verify_note_only_{int(row['DeviceID'])}"):
                        try:
                            note_text = verify_note.strip() or (
                                f"Review note for OOB={row['OOB']}; line={row['Line']}; "
                                f"health={row.get('Health', 'UNKNOWN')}."
                            )
                            update_device_verification(
                                device_id=int(row["DeviceID"]),
                                status=str(row.get("Verification") or "UNVERIFIED"),
                                source="operator_note",
                                ticket_ref=verify_ticket,
                                confidence=verify_confidence,
                                note=note_text,
                            )
                            audit(
                                "add_verification_note",
                                oob_id=row["OOBID"],
                                device_id=int(row["DeviceID"]),
                                detail=note_text,
                                ticket_ref=verify_ticket,
                                note=note_text,
                            )
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))

                if st.button("Edit inventory", width="stretch"):
                    st.session_state.device_edit_id = int(row["DeviceID"])
                    st.rerun()
            elif row["Mapping"] == "UNMANAGED":
                with st.expander("Assign to existing device"):
                    assign_candidates = [
                        d for d in list_devices()
                        if d.get("id") and (
                            d.get("expected_line") is None
                            or d.get("verification_status") != "VERIFIED"
                        )
                    ]
                    if not assign_candidates:
                        st.caption("No unverified or unassigned inventory device.")
                    else:
                        assign_labels = {
                            f"{d['hostname']} · {d.get('device_type') or '-'} · {d.get('site') or '-'}": d
                            for d in assign_candidates
                        }
                        assign_label = st.selectbox(
                            "Inventory device",
                            list(assign_labels),
                            key=f"assign_device_{row['OOBID']}_{row['Line']}",
                        )
                        assign_ticket = st.text_input(
                            "Ticket / change ref",
                            key=f"assign_ticket_{row['OOBID']}_{row['Line']}",
                        )
                        assign_confidence = st.slider(
                            "Confidence",
                            0.0,
                            1.0,
                            0.85,
                            0.05,
                            key=f"assign_confidence_{row['OOBID']}_{row['Line']}",
                        )
                        assign_note = st.text_area(
                            "Evidence note",
                            height=80,
                            key=f"assign_note_{row['OOBID']}_{row['Line']}",
                        )
                        if st.button(
                            "Assign line as verified",
                            width="stretch",
                            type="primary",
                            key=f"assign_line_{row['OOBID']}_{row['Line']}",
                        ):
                            try:
                                selected_device = assign_labels[assign_label]
                                default_note = (
                                    f"Assigned from detected line. OOB={row['OOB']}; line={row['Line']}; "
                                    f"alias={row['Alias'] or '-'}; health={row.get('Health', 'UNKNOWN')}."
                                )
                                assign_device_console_line(
                                    device_id=int(selected_device["id"]),
                                    oob_id=int(row["OOBID"]),
                                    line_no=int(row["Line"]),
                                    expected_alias=str(row["Alias"] or ""),
                                    ticket_ref=assign_ticket,
                                    confidence=assign_confidence,
                                    note=assign_note.strip() or default_note,
                                )
                                audit(
                                    "assign_detected_line",
                                    oob_id=int(row["OOBID"]),
                                    device_id=int(selected_device["id"]),
                                    detail=assign_note.strip() or default_note,
                                    ticket_ref=assign_ticket,
                                    note=assign_note.strip() or default_note,
                                )
                                st.rerun()
                            except Exception as exc:
                                st.error(str(exc))

                if st.button(
                    "Add discovered device",
                    width="stretch",
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

            a,b,c = st.columns(3)
            with a:
                inventory_source = st.text_input(
                    "Inventory Source",
                    value="" if is_new else existing.get("source", ""),
                    placeholder="CSV / Excel / NetBox / CMDB",
                )
            with b:
                inventory_source_id = st.text_input(
                    "Source ID",
                    value="" if is_new else existing.get("source_id", ""),
                )
            with c:
                last_imported_at = st.text_input(
                    "Last Imported At",
                    value="" if is_new else existing.get("last_imported_at", ""),
                    placeholder="YYYY-MM-DD HH:MM",
                )

            st.write("Verification")
            verify_statuses = ["UNVERIFIED", "VERIFIED", "STALE"]
            current_verify_status = (
                "UNVERIFIED" if is_new else (existing.get("verification_status") or "UNVERIFIED")
            )
            if current_verify_status not in verify_statuses:
                current_verify_status = "UNVERIFIED"
            a,b,c,d = st.columns(4)
            with a:
                verification_status = st.selectbox(
                    "Status",
                    verify_statuses,
                    index=verify_statuses.index(current_verify_status),
                )
            with b:
                verified_hostname = st.text_input(
                    "Verified Hostname",
                    value="" if is_new else existing.get("verified_hostname", ""),
                )
            with c:
                verified_serial = st.text_input(
                    "Verified Serial",
                    value="" if is_new else existing.get("verified_serial", ""),
                )
            with d:
                verified_model = st.text_input(
                    "Verified Model",
                    value="" if is_new else existing.get("verified_model", ""),
                )

            a,b,c = st.columns([1.2,1.2,2])
            with a:
                verified_at = st.text_input(
                    "Verified At",
                    value="" if is_new else existing.get("verified_at", ""),
                    placeholder="YYYY-MM-DD HH:MM",
                )
            with b:
                verified_by = st.text_input(
                    "Verified By",
                    value="" if is_new else existing.get("verified_by", ""),
                )
            with c:
                verification_source = st.text_input(
                    "Verification Source",
                    value="" if is_new else existing.get("verification_source", ""),
                    placeholder="show version / prompt / inventory",
                )

            a,b = st.columns([1.5,1])
            with a:
                verification_ticket_ref = st.text_input(
                    "Verification Ticket",
                    value="" if is_new else existing.get("verification_ticket_ref", ""),
                )
            with b:
                verification_confidence = st.slider(
                    "Confidence",
                    min_value=0.0,
                    max_value=1.0,
                    value=float(0 if is_new else existing.get("verification_confidence", 0) or 0),
                    step=0.05,
                    key=f"device_form_confidence_{edit_id}",
                )

            notes = st.text_area(
                "Notes",
                value="" if is_new else existing["notes"],
                height=75,
            )
            verification_note = st.text_area(
                "Verification Note",
                value="" if is_new else existing.get("verification_note", ""),
                height=70,
            )

            x,y,z = st.columns([1,1,4])
            save = x.form_submit_button("Save", type="primary", width="stretch")
            cancel = y.form_submit_button("Cancel", width="stretch")

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
                    source=inventory_source,
                    source_id=inventory_source_id,
                    last_imported_at=last_imported_at,
                    verification_status=verification_status,
                    verification_source=verification_source,
                    verified_hostname=verified_hostname,
                    verified_serial=verified_serial,
                    verified_model=verified_model,
                    verified_at=verified_at,
                    verified_by=verified_by,
                    verification_ticket_ref=verification_ticket_ref,
                    verification_confidence=verification_confidence,
                    verification_note=verification_note,
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
    st.caption("IP · SSH/API · profile · site")

    oob_df = pd.DataFrame(oobs)

    if not oob_df.empty:
        show_cols = [
            "id","name","vendor","profile_key","host",
            "port","username","site","updated_at"
        ]
        st.dataframe(
            styled_table(oob_df[show_cols]),
            width="stretch",
            hide_index=True,
            height=min(430, 75 + 35 * len(oob_df)),
        )
    else:
        render_empty_state("No OOB nodes yet.")

    c1,c2 = st.columns([1,4])

    if c1.button("+ Add OOB", type="primary", width="stretch"):
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
                    "SSH Port (CLI scan)",
                    1,
                    65535,
                    value=22 if oe == -1 else int(existing["port"]),
                    help="Vertiv API scan dùng API HTTPS Port ở màn Discovery, không dùng port SSH này.",
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
            save = x.form_submit_button("Save", type="primary", width="stretch")
            cancel = y.form_submit_button("Cancel", width="stretch")

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
    render_kpi(c2, "High", counts["HIGH"], "red", "mapping risk")
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
        render_empty_state("No matching events.")
    else:
        cols = [
            "id","severity","status","oob_name","line_no",
            "event_type","device_name","occurrence_count","last_seen","message"
        ]
        st.dataframe(
            styled_table(events_df[cols]),
            width="stretch",
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
                width="stretch",
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
                    width="stretch",
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
                    width="stretch",
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
                    width="stretch",
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
        render_empty_state("Add an OOB node first.")
    else:
        by_label = {
            f"{x['name']} · {x['host']} · {x['vendor']}": x
            for x in oobs
        }
        label = st.selectbox("OOB", list(by_label))
        target = by_label[label]
        target_profile_key = str(target.get("profile_key") or "")
        if target_profile_key not in profiles:
            st.error(
                "This OOB uses a removed or unsupported profile. "
                "Edit the OOB node and choose cisco or vertiv before scanning."
            )
            st.stop()
        profile = load_profile(target_profile_key)
        profile_commands = profile.get("commands", {})
        profile_line_commands = [
            str(cmd).strip()
            for cmd in profile_commands.get("lines", [])
            if str(cmd).strip()
        ]
        profile_api_supported = bool(profile.get("api_supported"))

        source_options: list[str] = []
        if profile_api_supported:
            source_options.append("Vertiv ACS API (read-only)")
        if profile_line_commands:
            source_options.append("OOB CLI qua Netmiko (read-only)")
        source_options.extend([
            "Console thiết bị phía sau OOB (chưa bật)",
            "SecureCRT/log terminal ngoài app (chưa bật)",
        ])
        selected_scan_source = st.selectbox(
            "Nguồn dữ liệu scan",
            source_options,
            help=(
                "OOB CLI/API là phần app đang tự đọc output. Console phía sau OOB "
                "và SecureCRT/log ngoài app sẽ làm sau để tránh rủi ro production."
            ),
        )
        use_vertiv_api = selected_scan_source == "Vertiv ACS API (read-only)"
        use_cli_scan = selected_scan_source == "OOB CLI qua Netmiko (read-only)"
        profile_ready = use_vertiv_api or use_cli_scan
        keep_cli_session = False

        api_port = int(profile.get("api_default_port", 48048))
        api_timeout = int(profile.get("api_timeout", 20))
        verify_tls = bool(profile.get("api_verify_tls_default", False))
        api_target_url = f"https://{target['host']}:{api_port}/api/v1/"
        if use_vertiv_api:
            st.info(
                "Vertiv ACS sẽ scan bằng REST API read-only: serial ports, active sessions, system info. "
                "Không gọi power on/off/cycle và không kill session."
            )
            api_a, api_b, api_c = st.columns([1, 1, 1])
            with api_a:
                api_port = int(
                    st.number_input(
                        "Vertiv API HTTPS Port",
                        min_value=1,
                        max_value=65535,
                        value=int(profile.get("api_default_port", 48048)),
                        step=1,
                    )
                )
            with api_b:
                api_timeout = int(
                    st.number_input(
                        "API Timeout (seconds)",
                        min_value=3,
                        max_value=45,
                        value=int(profile.get("api_timeout", 20)),
                        step=1,
                        help="Tăng giá trị này nếu ACS phản hồi chậm nhưng route/port chắc chắn đúng.",
                    )
                )
            with api_c:
                verify_tls = st.checkbox(
                    "Verify TLS certificate",
                    value=bool(profile.get("api_verify_tls_default", False)),
                    help="Bật nếu ACS dùng certificate hợp lệ. Tắt khi lab/OOB dùng self-signed certificate.",
                )
            api_target_url = f"https://{target['host']}:{api_port}/api/v1/"
            st.caption(
                f"Vertiv API target: {api_target_url} · "
                f"OOB SSH port {target['port']} không dùng cho scan API."
            )

        if use_cli_scan:
            keep_cli_session = st.checkbox(
                "Keep OOB session active for clear-line actions",
                value=False,
                help=(
                    "Bật nếu muốn sau scan vẫn giữ phiên SSH tới OOB để bấm clear line "
                    "không cần nhập lại password. Password vẫn không lưu database."
                ),
            )

        if not profile_ready:
            st.warning(
                "Nguồn dữ liệu này chưa có engine an toàn trong app. "
                "Hiện chỉ scan trực tiếp được OOB CLI qua Netmiko hoặc Vertiv ACS API read-only."
            )

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
                "Connect & Scan", type="primary", width="stretch",
                disabled=not profile_ready,
            )

        test_vertiv_api = False
        if use_vertiv_api:
            test_vertiv_api = st.button(
                "Test Vertiv API only",
                width="stretch",
                disabled=not profile_ready,
                help="Chỉ login API và đọc serial ports/sessions; không lưu snapshot, không tạo alert.",
            )

        if test_vertiv_api:
            if not username.strip() or not password:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = "Cần username/password để test Vertiv API. Password field đã được xóa."
                st.rerun()
            try:
                with st.spinner("Đang test Vertiv API read-only..."):
                    client = VertivACSClient(
                        host=target["host"],
                        port=api_port,
                        username=username,
                        password=password,
                        verify_tls=verify_tls,
                        timeout=api_timeout,
                    )
                    password = ""
                    check = preflight_vertiv_api(client)
                st.session_state["_clear_disc_pass"] = True
                if check["ok"]:
                    st.session_state["_flash_success"] = (
                        f"Vertiv API OK: đọc được {check['serial_port_count']} serial port, "
                        f"{check['session_count']} active session."
                    )
                else:
                    st.session_state["_flash_warning"] = check["message"]
                if check.get("session_error"):
                    st.session_state["_flash_warning"] = (
                        (st.session_state.get("_flash_warning") or "")
                        + " Sessions endpoint warning: "
                        + str(check["session_error"])
                    )
                st.rerun()
            except VertivAPIAuthenticationError:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = (
                    "Vertiv API login failed. Kiểm tra username/password và quyền REST API."
                )
                st.rerun()
            except VertivAPIError as exc:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = (
                    f"Vertiv API chưa sẵn sàng tại {api_target_url}: {exc}. "
                    "Kiểm tra API port, security profile/access rights, route/ACL hoặc TLS setting."
                )
                st.rerun()

        if connect_scan:
            if not username.strip() or not password:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = "Cần username/password. Password field đã được xóa."
                st.rerun()
            try:
                spinner_text = (
                    "Đang gọi Vertiv ACS API, normalize serial ports và compare snapshot..."
                    if use_vertiv_api
                    else "Đang SSH tuần tự, parse quality-check và compare snapshot..."
                )
                with st.spinner(spinner_text):
                    # Lock covers BOTH SSH connect and scan. No second browser/session can
                    # open another scan connection while this one is active.
                    with global_scan_lock():
                        if use_vertiv_api:
                            client = VertivACSClient(
                                host=target["host"],
                                port=api_port,
                                username=username,
                                password=password,
                                verify_tls=verify_tls,
                                timeout=api_timeout,
                            )
                            password = ""
                        else:
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
                            finally:
                                # Default is short-lived. Operator may keep it active for clear-line actions.
                                if not keep_cli_session:
                                    live.disconnect()

                        if use_vertiv_api:
                            result = scan_vertiv_api(
                                client,
                                oob_id=target["id"],
                                profile=profile,
                                acquire_lock=False,
                            )

                        st.session_state.last_scan = result
                        st.session_state.last_scan_oob_id = target["id"]
                        audit(
                            "scan",
                            oob_id=target["id"],
                            detail=(
                                f"transport={result.get('transport', 'SSH_CLI')}; "
                                f"accepted={result['accepted']}; rows={len(result['records'])}; "
                                f"events={result['change_count']}; quality={result['parse_quality']:.2f}"
                            ),
                        )

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
            except VertivAPIAuthenticationError:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = (
                    "Vertiv API authentication failed. Kiểm tra username/password và quyền REST API."
                )
                st.rerun()
            except VertivAPIError as exc:
                st.session_state["_clear_disc_pass"] = True
                st.session_state["_flash_error"] = f"Vertiv API error tại {api_target_url}: {exc}"
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
                    styled_table(rec_df), width="stretch", hide_index=True,
                    height=min(500, 75 + 35 * len(rec_df)),
                )

            if result["errors"]:
                with st.expander("Command fallback / transport errors"):
                    for error in result["errors"]:
                        st.code(error, language="text")

            with st.expander("Raw discovery output"):
                for kind, item in result["raw"].items():
                    label = item.get("command") or item.get("endpoint") or "no working command"
                    st.write(f"**{kind}** · `{label}`")
                    if "payload" in item:
                        body = json.dumps(item.get("payload"), ensure_ascii=False, indent=2)
                        st.code(body or "(empty)", language="json")
                    else:
                        st.code(item.get("output", "") or "(empty)", language="text")

# ==============================================================
# DATA
# ==============================================================
if active_page == "Data":
    st.subheader("Data Management")
    st.caption("Inventory · snapshots · alerts · audit")

    devices = list_devices()
    inv_df = pd.DataFrame(devices)

    a,b,c,d = st.columns(4)
    with a:
        if devices:
            csv = inv_df.to_csv(index=False).encode("utf-8-sig")
            st.download_button(
                "Export Inventory CSV", csv, "oob_inventory.csv", "text/csv",
                width="stretch",
            )
        else:
            st.button("Export Inventory CSV", disabled=True, width="stretch")
    with b:
        template_csv = pd.DataFrame(columns=IMPORT_FIELDS).to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Download Import Template",
            template_csv,
            "oob_inventory_template.csv",
            "text/csv",
            width="stretch",
        )
    with c:
        uploaded = st.file_uploader("Import CSV / Excel", type=["csv", "xlsx"], label_visibility="collapsed")
    with d:
        if st.button("Backup SQLite Now", width="stretch"):
            path = backup_db()
            keep = int(get_setting("backup_keep_count", "30"))
            removed = prune_backups(keep)
            audit("backup_db", detail=f"backup={path.name}; pruned={removed}")
            st.success(f"Backup: {path.name}")

    if uploaded is not None:
        try:
            filename = (uploaded.name or "").lower()
            if filename.endswith(".xlsx"):
                incoming = pd.read_excel(uploaded)
            else:
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
                    "expected_alias","mgmt_ip","rack","source","source_id","changed_fields"
                ]
                st.dataframe(
                    styled_table(preview_df[[c for c in show_cols if c in preview_df.columns]]),
                    width="stretch", hide_index=True,
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
    st.subheader("Daily Operations Analytics")
    st.caption("Trend by day · scans · parser quality · alerts · audit context")

    range_choice = st.radio(
        "Time range",
        ["24h", "7 days", "30 days", "90 days", "Custom range"],
        horizontal=True,
        key="data_analytics_range",
    )
    now_dt = datetime.now()
    if range_choice == "24h":
        start_dt = now_dt - timedelta(hours=24)
        end_dt = now_dt
        range_label = "last 24h"
    elif range_choice == "7 days":
        start_dt = datetime.combine(date.today() - timedelta(days=6), time.min)
        end_dt = now_dt
        range_label = "7 days"
    elif range_choice == "30 days":
        start_dt = datetime.combine(date.today() - timedelta(days=29), time.min)
        end_dt = now_dt
        range_label = "30 days"
    elif range_choice == "90 days":
        start_dt = datetime.combine(date.today() - timedelta(days=89), time.min)
        end_dt = now_dt
        range_label = "90 days"
    else:
        d1,d2 = st.columns(2)
        with d1:
            custom_start = st.date_input(
                "Start date",
                value=date.today() - timedelta(days=29),
                key="data_custom_start",
            )
        with d2:
            custom_end = st.date_input(
                "End date",
                value=date.today(),
                key="data_custom_end",
            )
        if custom_start > custom_end:
            st.warning("Start date is after end date; using end date for both.")
            custom_start = custom_end
        start_dt = datetime.combine(custom_start, time.min)
        end_dt = datetime.combine(custom_end, time.max)
        range_label = f"{custom_start.isoformat()} -> {custom_end.isoformat()}"

    start_ts = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_ts = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    daily_df = pd.DataFrame(analytics_daily_summary(start_ts, end_ts))
    severity_df = pd.DataFrame(analytics_alert_severity(start_ts, end_ts))
    scans_df = pd.DataFrame(list_scans_range(start_ts, end_ts, 500))
    issues_df = pd.DataFrame(list_scan_issues_range(start_ts, end_ts, 500))
    events_df = pd.DataFrame(list_change_events_range(start_ts, end_ts, limit=500))
    audit_df = pd.DataFrame(list_audit_range(start_ts, end_ts, limit=500))
    all_time_summary = history_summary(None)

    if daily_df.empty:
        total_scans = accepted_scans = rejected_scans = error_scans = 0
        total_snapshots = total_alert_new = total_alert_resolved = open_at_end = 0
        avg_quality = None
    else:
        total_scans = int(daily_df["scan_count"].sum())
        accepted_scans = int(daily_df["scan_accepted"].sum())
        rejected_scans = int(daily_df["scan_rejected"].sum())
        error_scans = int(daily_df["scan_error"].sum())
        total_snapshots = int(daily_df["snapshot_count"].sum())
        total_alert_new = int(daily_df["alert_new"].sum())
        total_alert_resolved = int(daily_df["alert_resolved"].sum())
        open_at_end = int(daily_df["alerts_open_end"].iloc[-1])
        quality_series = pd.to_numeric(daily_df["avg_parse_quality"], errors="coerce").dropna()
        avg_quality = float(quality_series.mean()) if not quality_series.empty else None

    k1,k2,k3,k4,k5,k6 = st.columns(6)
    render_kpi(k1, "Scans", total_scans, "cyan", range_label)
    render_kpi(k2, "Accepted", accepted_scans, "green", "quality gate pass")
    render_kpi(k3, "Rejected / Error", rejected_scans + error_scans, "red" if rejected_scans + error_scans else "green", "needs parser review")
    render_kpi(k4, "Snapshots", total_snapshots, "blue", "committed state")
    render_kpi(k5, "Alerts New / Resolved", f"{total_alert_new}/{total_alert_resolved}", "amber", "change events")
    render_kpi(k6, "Open Alerts", open_at_end, "red" if open_at_end else "green", "end of range")

    analytics_tab, detail_tab, foundation_tab, snapshot_tab = st.tabs(
        ["Analytics", "Recent Details", "OOB Foundations", "Snapshots"]
    )

    with analytics_tab:
        st.markdown(
            "<div class='section-note'>"
            "Daily view uses the selected time range. Rejected scans do not overwrite current state; they are shown here for parser and operations review."
            "</div>",
            unsafe_allow_html=True,
        )
        c1,c2 = st.columns(2)
        render_multi_line_chart(
            c1,
            "Scan Volume By Day",
            daily_df,
            "day",
            ["scan_count"],
            {"scan_count": "Scans"},
            height=220,
        )
        render_stacked_bar_chart(
            c2,
            "Accepted Vs Rejected Scans",
            daily_df,
            "day",
            ["scan_accepted", "scan_rejected", "scan_error"],
            {
                "scan_accepted": "Accepted",
                "scan_rejected": "Rejected",
                "scan_error": "Error",
            },
            height=220,
        )

        c3,c4 = st.columns(2)
        if severity_df.empty:
            severity_pivot = pd.DataFrame(columns=["day", "CRITICAL", "HIGH", "WARNING", "INFO"])
        else:
            severity_pivot = (
                severity_df.pivot_table(
                    index="day",
                    columns="severity",
                    values="count",
                    aggfunc="sum",
                    fill_value=0,
                )
                .reset_index()
                .rename_axis(None, axis=1)
            )
            for col in ["CRITICAL", "HIGH", "WARNING", "INFO"]:
                if col not in severity_pivot.columns:
                    severity_pivot[col] = 0
        render_stacked_bar_chart(
            c3,
            "Alert Severity By Day",
            severity_pivot,
            "day",
            ["CRITICAL", "HIGH", "WARNING", "INFO"],
            {
                "CRITICAL": "Critical",
                "HIGH": "High",
                "WARNING": "Warning",
                "INFO": "Info",
            },
            height=220,
        )
        render_multi_line_chart(
            c4,
            "Open / New / Resolved Alert Trend",
            daily_df,
            "day",
            ["alerts_open_end", "alert_new", "alert_resolved"],
            {
                "alerts_open_end": "Open",
                "alert_new": "New",
                "alert_resolved": "Resolved",
            },
            height=220,
        )

        c5,c6 = st.columns([1.25,1])
        render_multi_line_chart(
            c5,
            "Parse Quality Trend",
            daily_df,
            "day",
            ["avg_parse_quality"],
            {"avg_parse_quality": "Parse Quality"},
            height=220,
            y_title="quality",
        )
        render_bar_chart(
            c6,
            "Current Inventory Risk",
            [
                ("Detected", all_time_summary["detected"]),
                ("Open Events", all_time_summary["open_events"]),
                ("Rejected", rejected_scans),
                ("Warning", len(issues_df)),
            ],
            height=220,
        )

        if daily_df.empty:
            render_empty_state("No data in selected range.")
        else:
            daily_show = daily_df.rename(
                columns={
                    "day": "Day",
                    "scan_count": "Scans",
                    "scan_accepted": "Accepted",
                    "scan_rejected": "Rejected",
                    "scan_error": "Error",
                    "snapshot_count": "Snapshots",
                    "alert_new": "Alerts New",
                    "alert_resolved": "Alerts Resolved",
                    "alerts_open_end": "Open Alerts End",
                    "avg_parse_quality": "Avg Parse Quality",
                }
            )
            st.write("**Daily Summary Table**")
            st.dataframe(
                styled_table(daily_show),
                width="stretch",
                hide_index=True,
                height=min(430, 75 + 35 * len(daily_show)),
            )

    with detail_tab:
        scan_tab, issue_tab, event_tab, audit_tab = st.tabs(
            ["Scan History", "Scan Issues", "Change Events", "Audit"]
        )
        with scan_tab:
            if scans_df.empty:
                render_empty_state("No scans in selected range.")
            else:
                scan_cols = [
                    "id","oob_name","oob_host","started_at","finished_at","success",
                    "parse_status","parse_quality","line_count","error_text"
                ]
                st.dataframe(
                    styled_table(scans_df[[c for c in scan_cols if c in scans_df.columns]]),
                    width="stretch",
                    hide_index=True,
                    height=min(420, 75 + 35 * len(scans_df)),
                )
                scan_labels = {
                    f"#{row['id']} · {row['oob_name']} · {row['parse_status']} · {row['started_at']}": row
                    for row in scans_df.to_dict("records")
                }
                selected_scan = st.selectbox("Scan detail", list(scan_labels), label_visibility="collapsed")
                scan_row = scan_labels[selected_scan]
                if scan_row.get("error_text"):
                    st.code(scan_row["error_text"], language="text")
        with issue_tab:
            if issues_df.empty:
                render_empty_state("No parser or scan issues in selected range.")
            else:
                issue_cols = ["id","scan_id","oob_name","issue_type","severity","message","created_at"]
                st.dataframe(
                    styled_table(issues_df[[c for c in issue_cols if c in issues_df.columns]]),
                    width="stretch",
                    hide_index=True,
                    height=min(420, 75 + 35 * len(issues_df)),
                )
        with event_tab:
            if events_df.empty:
                render_empty_state("No change events in selected range.")
            else:
                severity_filter = st.selectbox(
                    "Severity filter",
                    ["ALL","CRITICAL","HIGH","WARNING","INFO"],
                    key="data_event_severity",
                )
                event_view = events_df.copy()
                if severity_filter != "ALL" and "severity" in event_view.columns:
                    event_view = event_view[event_view["severity"] == severity_filter]
                event_cols = [
                    "id","severity","status","oob_name","line_no","event_type",
                    "device_name","occurrence_count","first_seen","last_seen","resolved_at","message"
                ]
                st.dataframe(
                    styled_table(event_view[[c for c in event_cols if c in event_view.columns]]),
                    width="stretch",
                    hide_index=True,
                    height=min(460, 75 + 35 * len(event_view)),
                )
        with audit_tab:
            if audit_df.empty:
                render_empty_state("No audit entries in selected range.")
            else:
                a1,a2,a3 = st.columns(3)
                actors = ["ALL"] + sorted(audit_df["actor"].fillna("").astype(str).replace("", "unknown").unique().tolist())
                actions = ["ALL"] + sorted(audit_df["action"].fillna("").astype(str).replace("", "unknown").unique().tolist())
                oob_choices = {"ALL": None}
                oob_choices.update({x["name"]: x["id"] for x in oobs})
                with a1:
                    actor_filter = st.selectbox("Actor", actors, key="audit_actor_filter")
                with a2:
                    action_filter = st.selectbox("Action", actions, key="audit_action_filter")
                with a3:
                    audit_oob_label = st.selectbox("OOB", list(oob_choices), key="audit_oob_filter")
                audit_view = audit_df.copy()
                if actor_filter != "ALL":
                    audit_view = audit_view[audit_view["actor"].fillna("").astype(str).replace("", "unknown") == actor_filter]
                if action_filter != "ALL":
                    audit_view = audit_view[audit_view["action"].fillna("").astype(str).replace("", "unknown") == action_filter]
                audit_oob_id = oob_choices[audit_oob_label]
                if audit_oob_id is not None:
                    audit_view = audit_view[audit_view["oob_id"] == audit_oob_id]
                audit_cols = [
                    "ts","actor","source_host","source_ip","action","oob_id",
                    "device_id","ticket_ref","note","detail"
                ]
                st.dataframe(
                    styled_table(audit_view[[c for c in audit_cols if c in audit_view.columns]]),
                    width="stretch",
                    hide_index=True,
                    height=min(460, 75 + 35 * len(audit_view)),
                )

    with foundation_tab:
        foundation_df = pd.DataFrame(operational_foundation_summary())
        st.dataframe(
            styled_table(foundation_df),
            width="stretch",
            hide_index=True,
            height=min(380, 75 + 35 * len(foundation_df)),
        )

        f1,f2 = st.columns(2)
        with f1:
            st.write("**Verified Inventory Readiness**")
            devices_foundation_df = pd.DataFrame(list_devices())
            if devices_foundation_df.empty:
                render_empty_state("No devices yet.")
            else:
                verified_cols = [
                    "hostname","oob_name","expected_line","expected_alias",
                    "verification_status","verified_hostname","verified_serial",
                    "verification_confidence","verification_ticket_ref",
                    "verified_at","verified_by","source","source_id","verification_note"
                ]
                st.dataframe(
                    styled_table(devices_foundation_df[[c for c in verified_cols if c in devices_foundation_df.columns]]),
                    width="stretch",
                    hide_index=True,
                    height=min(360, 75 + 35 * len(devices_foundation_df)),
                )
        with f2:
            st.write("**Vendor Abstraction**")
            vendor_rows = []
            for key, data in profiles.items():
                command_total = sum(len(commands) for commands in data.get("commands", {}).values())
                vendor_rows.append(
                    {
                        "Profile": key,
                        "Vendor": data.get("vendor", key),
                        "Netmiko Type": data.get("netmiko_device_type", ""),
                        "Mapping": "READY" if data.get("mapping_supported") else "FOUNDATION",
                        "Commands": command_total,
                        "Notes": data.get("notes", ""),
                    }
                )
            st.dataframe(
                styled_table(pd.DataFrame(vendor_rows)),
                width="stretch",
                hide_index=True,
                height=min(360, 75 + 35 * max(1, len(vendor_rows))),
            )

        context_df = pd.DataFrame(list_terminal_contexts(100))
        power_df = pd.DataFrame(list_console_power_map(100))
        readiness_df = pd.DataFrame(list_readiness_checks(100))
        foundation_detail_1, foundation_detail_2, foundation_detail_3 = st.tabs(
            ["Terminal Context", "Power Mapping", "Readiness Checks"]
        )
        with foundation_detail_1:
            if context_df.empty:
                render_empty_state("No terminal context records yet. Foundation is ready; automation should remain guarded until context is recorded.")
            else:
                context_cols = [
                    "detected_at","oob_name","device_name","line_no","context_state",
                    "prompt","privilege_level","confidence","source"
                ]
                st.dataframe(
                    styled_table(context_df[[c for c in context_cols if c in context_df.columns]]),
                    width="stretch",
                    hide_index=True,
                )
        with foundation_detail_2:
            if power_df.empty:
                render_empty_state("No console-to-power mappings yet. Reboot actions stay manual until outlet mapping is verified.")
            else:
                power_cols = [
                    "id","oob_name","device_name","line_no","pdu_name","pdu_host",
                    "outlet_label","control_mode","verified_at","notes"
                ]
                st.dataframe(
                    styled_table(power_df[[c for c in power_cols if c in power_df.columns]]),
                    width="stretch",
                    hide_index=True,
                )

            p1,p2,p3 = st.columns([1,2,1])
            if p1.button("+ Power Map", width="stretch"):
                st.session_state.power_map_edit_id = -1
                st.rerun()

            selected_power_row = None
            if not power_df.empty:
                power_labels = {
                    f"#{row['id']} · {row['oob_name']} · line {row.get('line_no') if has_value(row.get('line_no')) else '-'} · {row['pdu_name']}:{row['outlet_label']}": row
                    for row in power_df.to_dict("records")
                }
                selected_power_label = p2.selectbox(
                    "Power mapping",
                    list(power_labels),
                    label_visibility="collapsed",
                    key="selected_power_mapping",
                )
                selected_power_row = power_labels[selected_power_label]
                if p3.button("Edit selected", width="stretch"):
                    st.session_state.power_map_edit_id = int(selected_power_row["id"])
                    st.rerun()

                delete_power = st.checkbox(
                    "Confirm delete selected power mapping.",
                    key="confirm_delete_power_mapping",
                )
                if st.button(
                    "Delete selected power mapping",
                    disabled=not delete_power,
                    width="stretch",
                ):
                    delete_console_power_map(int(selected_power_row["id"]))
                    audit(
                        "delete_power_mapping",
                        oob_id=selected_power_row.get("oob_id"),
                        device_id=int(selected_power_row["device_id"]) if has_value(selected_power_row.get("device_id")) else None,
                        detail=f"mapping={selected_power_row['id']}",
                    )
                    st.session_state.power_map_edit_id = None
                    st.rerun()

            pm_edit_id = st.session_state.power_map_edit_id
            if pm_edit_id is not None:
                existing_power = None
                if pm_edit_id != -1 and not power_df.empty:
                    matches = [r for r in power_df.to_dict("records") if int(r["id"]) == int(pm_edit_id)]
                    existing_power = matches[0] if matches else None

                st.write("**Add Power Mapping**" if pm_edit_id == -1 else "**Edit Power Mapping**")
                if not oobs:
                    st.warning("Add an OOB node first.")
                else:
                    device_rows_for_power = list_devices()
                    power_oob_options = {x["name"]: x["id"] for x in oobs}
                    default_power_oob = next(
                        (
                            i for i, name in enumerate(power_oob_options)
                            if existing_power and power_oob_options[name] == existing_power.get("oob_id")
                        ),
                        0,
                    )
                    device_options = {"(No device)": None}
                    device_options.update({d["hostname"]: d["id"] for d in device_rows_for_power})
                    default_power_device = next(
                        (
                            i for i, name in enumerate(device_options)
                            if existing_power
                            and has_value(existing_power.get("device_id"))
                            and device_options[name] == int(existing_power.get("device_id"))
                        ),
                        0,
                    )
                    existing_line_text = ""
                    if existing_power and has_value(existing_power.get("line_no")):
                        existing_line_text = str(int(float(existing_power.get("line_no"))))
                    with st.form("power_map_form"):
                        a,b,c = st.columns([1.4,1.4,1])
                        with a:
                            power_oob_name = st.selectbox(
                                "OOB",
                                list(power_oob_options),
                                index=default_power_oob,
                            )
                        with b:
                            power_device_name = st.selectbox(
                                "Device",
                                list(device_options),
                                index=default_power_device,
                            )
                        with c:
                            power_line_text = st.text_input(
                                "Line",
                                value=existing_line_text,
                            )
                        a,b,c = st.columns(3)
                        with a:
                            pdu_name = st.text_input(
                                "PDU Name",
                                value="" if not existing_power else existing_power.get("pdu_name", ""),
                            )
                        with b:
                            pdu_host = st.text_input(
                                "PDU Host",
                                value="" if not existing_power else existing_power.get("pdu_host", ""),
                            )
                        with c:
                            outlet_label = st.text_input(
                                "Outlet Label",
                                value="" if not existing_power else existing_power.get("outlet_label", ""),
                            )
                        a,b = st.columns([1,2])
                        with a:
                            control_mode = st.selectbox("Control Mode", ["MANUAL"], index=0)
                        with b:
                            power_verified_at = st.text_input(
                                "Verified At",
                                value="" if not existing_power else existing_power.get("verified_at", "") or "",
                            )
                        power_notes = st.text_area(
                            "Notes",
                            value="" if not existing_power else existing_power.get("notes", "") or "",
                            height=80,
                        )
                        save_power = st.form_submit_button("Save Power Mapping", type="primary")
                        cancel_power = st.form_submit_button("Cancel")

                    if cancel_power:
                        st.session_state.power_map_edit_id = None
                        st.rerun()
                    if save_power:
                        try:
                            power_line_no = int(power_line_text) if power_line_text.strip() else None
                            mapping_id = save_console_power_map(
                                mapping_id=None if pm_edit_id == -1 else int(pm_edit_id),
                                oob_id=power_oob_options[power_oob_name],
                                device_id=device_options[power_device_name],
                                line_no=power_line_no,
                                pdu_name=pdu_name,
                                pdu_host=pdu_host,
                                outlet_label=outlet_label,
                                control_mode=control_mode,
                                verified_at=power_verified_at,
                                notes=power_notes,
                            )
                            audit(
                                "save_power_mapping",
                                oob_id=power_oob_options[power_oob_name],
                                device_id=device_options[power_device_name],
                                detail=f"mapping={mapping_id};line={power_line_no};pdu={pdu_name};outlet={outlet_label}",
                                note=power_notes,
                            )
                            st.session_state.power_map_edit_id = None
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
        with foundation_detail_3:
            if readiness_df.empty:
                render_empty_state("No disaster readiness checks recorded yet. Use this foundation for reachability, port response, and credential-validity checks.")
            else:
                readiness_cols = [
                    "created_at","checked_at","next_check_at","oob_name","device_name",
                    "line_no","check_type","status","message","evidence"
                ]
                st.dataframe(
                    styled_table(readiness_df[[c for c in readiness_cols if c in readiness_df.columns]]),
                    width="stretch",
                    hide_index=True,
                )

        st.write("**Safe Automation Guardrails**")
        guardrail_df = pd.DataFrame(
            [
                {
                    "Guard": "Context required",
                    "Why": "Prevents show commands from running on OOB while operator expects target device.",
                    "Default": "BLOCK until context is OOB or TARGET with confidence.",
                },
                {
                    "Guard": "Show-only scope",
                    "Why": "Batch automation must not enter config/reboot/power control paths.",
                    "Default": "ALLOW only show/display discovery commands.",
                },
                {
                    "Guard": "Verified target",
                    "Why": "Alias alone is not identity; target should be verified by prompt/show output.",
                    "Default": "WARN for unverified/stale inventory.",
                },
                {
                    "Guard": "Ticket/note",
                    "Why": "Makes audit readable for NOC handoff and incident review.",
                    "Default": "Prepare ticket_ref/note fields; no secret storage.",
                },
            ]
        )
        st.dataframe(guardrail_df, width="stretch", hide_index=True, height=220)

    with snapshot_tab:
        s1,s2 = st.columns([2,1])
        with s1:
            snapshot_oob = st.selectbox(
                "Snapshot OOB", ["ALL"] + [x["name"] for x in oobs], key="snapshot_oob"
            )
        with s2:
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

        snapshots = list_snapshots_range(
            start_ts,
            end_ts,
            oob_id=oob_id_filter,
            line_no=line_filter,
            limit=700,
        )
        snapshots_df = pd.DataFrame(snapshots)
        if not snapshots_df.empty:
            st.dataframe(
                styled_table(snapshots_df[[
                    "id","scan_id","oob_name","line_no","alias","tcp_port",
                    "state","session_user","session_health","captured_at"
                ]]),
                width="stretch",
                hide_index=True,
                height=min(520, 75 + 35 * len(snapshots_df)),
            )
        else:
            render_empty_state("No matching snapshots in selected range.")

# ==============================================================
# SETTINGS
# ==============================================================
if active_page == "Settings":
    st.subheader("Operations Settings")
    st.caption("Terminal defaults · retention · backups")

    launcher_tab, retention_tab = st.tabs(["Terminal Launchers", "Retention & Backups"])

    with launcher_tab:
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
                "Management default",
                ["Windows SSH", "SecureCRT SSH"],
                index=0 if get_setting("mgmt_launcher", "Windows SSH") == "Windows SSH" else 1,
            )
        if st.button("Save Launcher Settings", width="stretch", type="primary"):
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

    with retention_tab:
        st.write("**Retention & Backups**")
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
        if s1.button("Save Retention Settings", width="stretch", type="primary"):
            set_setting("snapshot_retention_days", str(int(snapshot_days)))
            set_setting("scan_raw_retention_days", str(int(raw_days)))
            set_setting("backup_keep_count", str(int(backup_keep)))
            audit("save_retention_settings", detail=f"snapshot={snapshot_days};raw={raw_days};backup={backup_keep}")
            st.success("Đã lưu. Scanner sẽ auto-prune sau mỗi accepted scan.")
        if s2.button("Prune History Now", width="stretch"):
            result = prune_history(int(snapshot_days), int(raw_days))
            removed = prune_backups(int(backup_keep))
            audit("prune_history", detail=f"{result}; backups_removed={removed}")
            st.success(f"Prune hoàn tất: {result}, backups_removed={removed}")

        st.code(
            "setup_daily_backup.bat  -> daily backup 02:00\n"
            "remove_daily_backup_task.bat -> remove task",
            language="text",
        )

st.caption(
    "Hardened · local-only · scan lock · quality gate · audit · backup"
)
