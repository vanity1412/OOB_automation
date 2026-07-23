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

from core.connection import LiveOOB
from core.database import audit, backup_db, init_db, prune_backups
from core.importer import apply_inventory_import, preview_inventory_import
from core.profiles import list_profiles, load_profile, save_profile
from core.repository import (
    analytics_alert_severity,
    analytics_daily_summary,
    count_open_events,
    delete_device,
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
    list_readiness_checks,
    list_scan_issues_range,
    list_scans_range,
    list_snapshots_range,
    list_terminal_contexts,
    operational_foundation_summary,
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

FPT_LOGO_PATH = Path(__file__).resolve().parent / "assets" / "fpt_telecom_logo.jpg"


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
    "STALE_SESSION": "amber",
    "NO_OUTPUT": "red",
    "BOOTLOADER": "amber",
    "WRONG_BAUD": "red",
    "OOB": "blue",
    "TARGET": "green",
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
    status = str(row.get("Status", "") or "").upper()
    verification = str(row.get("Verification", "") or "").upper()
    severity = str(row.get("severity", "") or "").upper()
    action = str(row.get("action", "") or "").upper()

    bg = ""
    if mapping in {"MISMATCH", "NOT DETECTED"} or verification == "STALE" or severity in {"CRITICAL", "HIGH"}:
        bg = "background-color:#fff5f5;"
    elif mapping == "UNMANAGED" or verification == "UNVERIFIED" or status == "BUSY" or severity == "WARNING" or action == "UPDATE":
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
        for col in ("Status", "Mapping", "Verification", "severity", "status", "state", "parse_status", "action")
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
    st.markdown(
        "<div class='sidebar-stats-card'>"
        "<div class='sidebar-status' style='--sidebar-dot:{live_dot};'>"
        "<span class='sidebar-dot'></span><span>{live_label}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>OOB Nodes</span>"
        "<span class='sidebar-stat-value'>{oob_count}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Open Alerts</span>"
        "<span class='sidebar-stat-value' style='{alert_style}'>{alert_count}</span></div>"
        "<div class='sidebar-stat-row'><span class='sidebar-stat-label'>Scan Mode</span>"
        "<span class='sidebar-stat-value'>Serial lock</span></div>"
        "</div>".format(
            live_dot=live_dot,
            live_label=html.escape(live_label),
            oob_count=len(oobs),
            alert_count=header_open_alerts,
            alert_style=alert_style,
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
        if st.button("+ Device", type="primary", width="stretch"):
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
        "Alias","Status","Session","Mapping","Verification","Last Seen"
    ]

    if shown.empty:
        render_empty_state("No data. Add OOB, then Connect & Scan.")
    else:
        st.dataframe(
            styled_table(shown[table_cols]),
            width="stretch",
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
                ["Verification", row.get("Verification", "-") or "-"],
                ["Verified Hostname", row.get("Verified Hostname", "-") or "-"],
                ["Verified Serial", row.get("Verified Serial", "-") or "-"],
                ["Last Seen", row["Last Seen"] or "-"],
            ], columns=["Field","Value"])
            st.dataframe(
                detail.astype(str),
                width="stretch",
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

            if has_value(row["TCP Port"]) and has_value(row["OOB Host"]):
                tcp_port = as_port(row["TCP Port"])
                st.code(
                    f"telnet {row['OOB Host']} {tcp_port}",
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
                        if console_uses_securecrt:
                            launch_securecrt_telnet(row["OOB Host"], tcp_port, securecrt_path)
                            audit(
                                "launch_securecrt_console",
                                oob_id=row["OOBID"],
                                device_id=row["DeviceID"],
                                detail=f"{row['Device']}:{tcp_port}",
                            )
                            st.toast("SecureCRT console opened.")
                        else:
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
                with st.expander("Other console launcher"):
                    if console_uses_securecrt:
                        if st.button("Open with Windows Telnet", width="stretch"):
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
                    else:
                        if st.button("Open with SecureCRT", width="stretch"):
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
                if st.button("Edit inventory", width="stretch"):
                    st.session_state.device_edit_id = int(row["DeviceID"])
                    st.rerun()
            elif row["Mapping"] == "UNMANAGED":
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
                    verification_status=verification_status,
                    verification_source=verification_source,
                    verified_hostname=verified_hostname,
                    verified_serial=verified_serial,
                    verified_model=verified_model,
                    verified_at=verified_at,
                    verified_by=verified_by,
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
    st.caption("IP · SSH · profile · site")

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
                "Connect & Scan", type="primary", width="stretch"
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
                    styled_table(rec_df), width="stretch", hide_index=True,
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
                width="stretch",
            )
        else:
            st.button("Export Inventory CSV", disabled=True, width="stretch")
    with b:
        uploaded = st.file_uploader("Import CSV", type=["csv"], label_visibility="collapsed")
    with c:
        if st.button("Backup SQLite Now", width="stretch"):
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
                    "verified_at","verified_by","verification_note"
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
                    "oob_name","device_name","line_no","pdu_name","pdu_host",
                    "outlet_label","control_mode","verified_at","notes"
                ]
                st.dataframe(
                    styled_table(power_df[[c for c in power_cols if c in power_df.columns]]),
                    width="stretch",
                    hide_index=True,
                )
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
                    "state","session_user","captured_at"
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
