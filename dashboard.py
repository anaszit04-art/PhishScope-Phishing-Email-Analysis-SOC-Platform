
"""
PhishScope — Emerald SOC Dashboard
Version: UI redesign for v1.1

A dark emerald security operations dashboard inspired by
modern SOC consoles.

Reads original PhishScope investigation reports and
uses the existing case-management API.

Local single-user application. Never expose publicly.
"""

import html
import math
from collections import Counter

import streamlit as st

from src.dashboard_data import (
    get_risk,
    load_reports,
    summarize_all,
)
from src.case_manager import (
    VALID_STATUSES,
    add_note,
    load_case,
    update_status,
)
from src.case_export import (
    build_analyst_export,
    export_json_bytes,
    export_text,
)


st.set_page_config(
    page_title="PhishScope | Emerald SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CSS = """
<style>
:root {
  --ps-bg: #060c09;
  --ps-surface: #0c1711;
  --ps-border: #1c3828;
  --ps-green: #5af2a1;
  --ps-text: #e7fff1;
  --ps-muted: #88a995;
}

html, body, [data-testid="stAppViewContainer"] {
  background:
    radial-gradient(
      ellipse 65% 35% at 88% 1%,
      rgba(25, 130, 76, .15),
      transparent 75%
    ),
    radial-gradient(
      ellipse 40% 42% at 15% 95%,
      rgba(7, 94, 52, .11),
      transparent 80%
    ),
    #060c09 !important;
}

[data-testid="stHeader"] {
  background: transparent !important;
}

[data-testid="stSidebar"] {
  background:
    linear-gradient(
      180deg,
      #0b1a12 0%,
      #07100b 100%
    ) !important;
  border-right: 1px solid #21422e;
}

[data-testid="stSidebar"] * {
  color: #d7f4e1;
}

.block-container {
  padding-top: 1.6rem;
  padding-bottom: 3rem;
  max-width: 1500px;
}

h1, h2, h3, h4 {
  color: #e8fff2 !important;
  letter-spacing: -.025em;
}

p, label {
  color: #b0cbbb;
}

[data-testid="stMetric"] {
  background:
    linear-gradient(
      145deg,
      rgba(28, 69, 44, .52),
      rgba(11, 24, 16, .97)
    );
  border: 1px solid #254d34;
  border-radius: 17px;
  padding: 18px 20px;
  min-height: 116px;
  box-shadow:
    inset 0 1px rgba(113, 255, 166, .06),
    0 12px 36px rgba(0, 0, 0, .18);
}

[data-testid="stMetricLabel"] {
  color: #92b39f !important;
  font-size: .82rem;
}

[data-testid="stMetricValue"] {
  color: #e9fff3 !important;
  font-weight: 720;
}

[data-testid="stMetricDelta"] {
  color: #65ef9f !important;
}

[data-testid="stVerticalBlockBorderWrapper"] {
  border-color: #244632 !important;
  border-radius: 18px !important;
  background: rgba(13, 27, 18, .68);
}

[data-testid="stDataFrame"] {
  border: 1px solid #244632;
  border-radius: 12px;
  overflow: hidden;
}

[data-baseweb="tab-list"] {
  background: rgba(10, 24, 15, .8);
  border-radius: 12px;
  padding: 5px 9px;
}

[data-baseweb="tab"] {
  color: #a7c8b2 !important;
}

[data-baseweb="tab"][aria-selected="true"] {
  color: #67f5a6 !important;
}

[data-baseweb="input"],
[data-baseweb="select"] > div,
textarea {
  background: #101f16 !important;
  border-color: #2a5137 !important;
  border-radius: 10px !important;
}

.stButton > button,
.stDownloadButton > button {
  background:
    linear-gradient(
      115deg,
      #154e30,
      #1e7547
    );
  color: #ebfff2 !important;
  border: 1px solid #388b58 !important;
  border-radius: 10px;
  font-weight: 600;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
  background: #267d4e;
  border-color: #73f6a8 !important;
  box-shadow: 0 0 22px rgba(49, 216, 120, .14);
}

[data-testid="stExpander"] {
  border: 1px solid #254a34 !important;
  background: #0c1911;
  border-radius: 11px;
}

.ps-header {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: center;
  padding: 18px 21px;
  margin-bottom: 24px;
  border: 1px solid #275039;
  border-radius: 19px;
  background:
    linear-gradient(
      110deg,
      rgba(22, 70, 43, .75),
      rgba(9, 22, 15, .94) 65%
    );
  box-shadow: 0 12px 42px rgba(0, 0, 0, .15);
}

.ps-brand {
  color: #effff4;
  font-size: 26px;
  font-weight: 800;
  letter-spacing: -.8px;
}

.ps-brand span {
  color: #5cf3a2;
}

.ps-kicker {
  text-transform: uppercase;
  letter-spacing: 2px;
  color: #8fb9a1;
  font-size: 10px;
  font-weight: 700;
}

.ps-pill {
  color: #83f5b4;
  background: rgba(42, 156, 86, .15);
  border: 1px solid #317c4b;
  padding: 8px 13px;
  border-radius: 30px;
  white-space: nowrap;
  font-size: 11px;
  font-weight: 700;
}

.ps-title {
  margin: 10px 0 6px;
  color: #eafff2;
  font-size: 23px;
  font-weight: 750;
}

.ps-subtitle {
  color: #91b09a;
  font-size: 13px;
  margin-bottom: 22px;
}

.ps-panel {
  padding: 20px 22px;
  border-radius: 17px;
  background:
    linear-gradient(
      150deg,
      rgba(21, 54, 34, .7),
      rgba(10, 21, 14, .98)
    );
  border: 1px solid #264d35;
  min-height: 210px;
}

.ps-panel-title {
  font-size: 14px;
  font-weight: 700;
  color: #e6fff0;
  margin-bottom: 14px;
}

.ps-muted {
  color: #89ad97;
  font-size: 12px;
}

.ps-risk-value {
  color: #72f6ad;
  font-size: 33px;
  font-weight: 800;
}

.ps-meter {
  height: 9px;
  border-radius: 30px;
  background: #193825;
  overflow: hidden;
  margin: 13px 0;
}

.ps-meter-fill {
  height: 100%;
  border-radius: 30px;
  background: linear-gradient(90deg, #23a96a, #72fca7);
}

.ps-breakdown {
  padding: 9px 0;
  display: flex;
  justify-content: space-between;
  border-bottom: 1px solid #1e3829;
  color: #bbd7c3;
  font-size: 13px;
}

.ps-insight {
  background:
    linear-gradient(
      125deg,
      #122d1d,
      #0b1a12
    );
  border: 1px solid #28543a;
  border-radius: 14px;
  padding: 16px 19px;
  margin: 12px 0;
}

.ps-insight-head {
  color: #e6fff0;
  font-weight: 700;
}

.ps-insight-body {
  color: #93b29e;
  font-size: 12px;
  margin-top: 6px;
}

.ps-divider {
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    #315e40,
    transparent
  );
  margin: 25px 0;
}

@media (max-width: 800px) {
  .ps-header { flex-wrap: wrap; }
  .ps-brand { font-size: 22px; }
  .block-container { padding-top: 1rem; }
}
</style>
"""


def safe(value):
    """Escape dynamic strings inserted into decorative HTML."""
    return html.escape(str(value), quote=True)


def panel(title, body):
    st.markdown(
        '<div class="ps-panel">'
        f'<div class="ps-panel-title">{safe(title)}</div>'
        f'{body}'
        '</div>',
        unsafe_allow_html=True,
    )


def metric_html(label, value, percent):
    percent = min(100, max(0, float(percent)))
    return (
        f'<div class="ps-muted">{safe(label)}</div>'
        f'<div class="ps-risk-value">{safe(value)}</div>'
        '<div class="ps-meter">'
        f'<div class="ps-meter-fill" '
        f'style="width:{percent:.1f}%"></div>'
        '</div>'
    )


def get_email(report):
    value = report.get("email_analysis")
    return value if isinstance(value, dict) else {}


def get_subject(report):
    headers = get_email(report).get("headers") or {}
    return str(headers.get("subject") or "Untitled email")


def get_findings(report):
    advanced = report.get("advanced_detection") or {}
    return advanced.get("findings") or []


def get_iocs(report):
    email = get_email(report)
    return email.get("iocs") or {}


def get_techniques(report):
    mitre = report.get("mitre_analysis") or {}
    return mitre.get("technique_candidates") or []


def get_priority(report):
    risk = report.get("risk_assessment") or {}
    return str(risk.get("review_priority") or "not_assessed")


def read_status(case_id):
    try:
        return load_case(case_id).get("status", "open")
    except (ValueError, OSError) as exc:
        st.warning(
            f"Could not read case status for {case_id}: {exc}"
        )
        return "unavailable"


def build_queue(reports):
    rows = []

    for report in reports:
        cid = str(report.get("case_id", ""))
        rows.append({
            "Case ID": cid[:8],
            "Subject": get_subject(report),
            "Risk": get_risk(report),
            "Priority": get_priority(report),
            "Findings": len(get_findings(report)),
            "URLs": get_iocs(report).get("total_urls", 0),
            "Status": read_status(cid),
            "Generated": str(
                report.get("generated_at") or ""
            )[:19],
        })

    return rows


def render_distribution(reports):
    priorities = Counter(get_priority(r) for r in reports)
    total = len(reports)

    values = [
        ("High", priorities.get("high", 0)),
        ("Elevated", priorities.get("elevated", 0)),
        ("Routine", priorities.get("routine", 0)),
        ("Low", priorities.get("low", 0)),
        ("Unassessed", priorities.get("not_assessed", 0)),
    ]

    body = f'<div class="ps-muted">{total} total cases</div>'

    for label, count in values:
        pct = 100 * count / total if total else 0
        body += (
            '<div class="ps-breakdown">'
            f'<span>{safe(label)}</span>'
            f'<strong>{count}</strong>'
            '</div>'
            '<div class="ps-meter">'
            f'<div class="ps-meter-fill" '
            f'style="width:{pct:.1f}%"></div>'
            '</div>'
        )

    panel("Investigation priorities", body)


def render_risk_overview(reports):
    scored = [
        get_risk(r)
        for r in reports
        if get_risk(r) is not None
    ]

    average = sum(scored) / len(scored) if scored else 0

    body = metric_html(
        "Average heuristic review score",
        f"{average:.1f}/100" if scored else "Not assessed",
        average
    )

    body += (
        '<div class="ps-muted">'
        f"{len(scored)} scored investigations "
        f"out of {len(reports)} total"
        '</div>'
    )

    panel("Risk intelligence", body)


def render_sidebar():
    st.sidebar.markdown("## 🛡️ PhishScope")
    st.sidebar.caption("EMERALD SOC · LOCAL CONSOLE")
    st.sidebar.divider()

    view = st.sidebar.radio(
        "Workspace",
        [
            "Overview",
            "Investigations",
            "Case Management",
            "Threat Intelligence",
            "Evidence & Export",
        ],
    )

    st.sidebar.divider()

    analyst = st.sidebar.text_input(
        "Analyst label",
        value="SOC Analyst",
        max_chars=80,
    )

    if st.sidebar.button("↻ Refresh investigations"):
        st.rerun()

    st.sidebar.caption(
        "Offline investigation console. "
        "No user authentication is provided."
    )

    return view, analyst


def render_overview(reports):
    stats = summarize_all(reports)

    st.markdown(
        '<div class="ps-title">Security Operations Overview</div>'
        '<div class="ps-subtitle">'
        'Investigation activity and email threat intelligence'
        '</div>',
        unsafe_allow_html=True,
    )

    scored = [
        get_risk(r)
        for r in reports
        if get_risk(r) is not None
    ]

    elevated = sum(
        get_priority(r) in ("high", "elevated")
        for r in reports
    )

    open_cases = sum(
        read_status(r["case_id"]) != "closed"
        for r in reports
    )

    a, b, c, d = st.columns(4)

    a.metric("Total Investigations", stats["total_cases"])
    b.metric("Active Cases", open_cases)
    c.metric("Scored Cases", len(scored))
    d.metric("Elevated / High", elevated)

    st.write("")

    left, right = st.columns([1.1, 1])

    with left:
        render_risk_overview(reports)

    with right:
        render_distribution(reports)

    st.markdown(
        '<div class="ps-divider"></div>',
        unsafe_allow_html=True,
    )

    st.markdown("### Recent Investigations")

    st.dataframe(
        build_queue(reports[:10]),
        width="stretch",
        hide_index=True,
    )

    st.markdown("### Detection Insights")

    selected = next(
        (
            r for r in reports
            if get_findings(r)
        ),
        None,
    )

    if selected:
        for item in get_findings(selected)[:4]:
            rule = item.get("rule_id") or "Detection"
            description = (
                item.get("description")
                or item.get("title")
                or "Additional analyst review required"
            )

            st.markdown(
                '<div class="ps-insight">'
                f'<div class="ps-insight-head">{safe(rule)}</div>'
                f'<div class="ps-insight-body">'
                f'{safe(description)}'
                '</div></div>',
                unsafe_allow_html=True,
            )
    else:
        st.info(
            "No advanced findings in the loaded cases."
        )


def select_report(reports, key="selected_case"):
    query = st.text_input(
        "Search investigations",
        placeholder="Case ID or subject...",
        key=f"{key}_query",
    )

    priority = st.selectbox(
        "Review priority",
        ["all", "high", "elevated", "routine",
         "low", "not_assessed"],
        key=f"{key}_priority",
    )

    filtered = [
        r for r in reports
        if (
            query.lower() in (
                str(r.get("case_id", ""))
                + " " + get_subject(r)
            ).lower()
            and (
                priority == "all"
                or get_priority(r) == priority
            )
        )
    ]

    if not filtered:
        st.info("No investigations match these filters.")
        return None

    lookup = {
        str(r["case_id"]): r
        for r in filtered
    }

    chosen = st.selectbox(
        "Select investigation",
        options=list(lookup),
        format_func=lambda cid: (
            f"{cid[:8]} · {get_subject(lookup[cid])[:75]}"
        ),
        key=key,
    )

    return lookup[chosen]


def render_findings(report):
    findings = get_findings(report)

    if not findings:
        st.info("No advanced detection findings recorded.")
        return

    for finding in findings:
        title = str(
            finding.get("rule_id") or "Detection"
        )
        severity = str(
            finding.get("severity") or "unknown"
        )

        with st.expander(
            f"{title} · {severity.upper()}"
        ):
            st.code(
                str(
                    finding.get("description")
                    or finding.get("title")
                    or finding
                ),
                language=None,
            )


def render_investigations(reports):
    st.markdown("## 🔎 Investigation Workspace")

    report = select_report(reports, "investigate")

    if report is None:
        return

    cid = report["case_id"]
    score = get_risk(report)

    st.code(cid, language=None)

    a, b, c, d = st.columns(4)

    a.metric("Heuristic Risk", (
        f"{score}/100" if score is not None else "N/A"
    ))
    b.metric("Priority", get_priority(report))
    c.metric("Findings", len(get_findings(report)))
    d.metric("URLs", get_iocs(report).get("total_urls", 0))

    tabs = st.tabs([
        "Email",
        "Detections",
        "Indicators",
        "ATT&CK",
        "Original report",
    ])

    with tabs[0]:
        email = get_email(report)
        st.subheader("Email evidence")

        headers = email.get("headers") or {}

        for field in [
            "subject",
            "sender_address",
            "reply_to_address",
        ]:
            st.caption(field.replace("_", " ").title())
            st.code(
                str(headers.get(field) or "Not recorded"),
                language=None,
            )

        attachments = email.get("attachments") or []
        st.metric("Attachments", len(attachments))

    with tabs[1]:
        render_findings(report)

    with tabs[2]:
        st.caption(
            "Indicators are inert text. "
            "Do not visit suspicious URLs."
        )
        details = get_iocs(report).get("url_details") or []

        for index, item in enumerate(details, start=1):
            with st.expander(f"Indicator {index}"):
                st.code(
                    str(item.get("url") or ""),
                    language=None,
                )
                st.code(
                    str(item.get("hostname") or ""),
                    language=None,
                )

    with tabs[3]:
        st.caption(
            "ATT&CK mappings are investigative "
            "candidates, not proof of execution."
        )

        techniques = get_techniques(report)

        if techniques:
            st.dataframe(
                techniques,
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No technique candidates recorded.")

    with tabs[4]:
        st.json(report)


def render_case_management(reports, analyst):
    st.markdown("## 🗂️ SOC Case Management")

    report = select_report(reports, "manage")

    if report is None:
        return

    cid = report["case_id"]

    try:
        record = load_case(cid)
    except (ValueError, OSError) as exc:
        st.error(f"Case metadata error: {exc}")
        return

    st.metric("Current Status", record["status"])

    current = record["status"]

    selected_status = st.selectbox(
        "Update investigation status",
        list(VALID_STATUSES),
        index=(
            list(VALID_STATUSES).index(current)
            if current in VALID_STATUSES else 0
        ),
    )

    if st.button("Save Case Status"):
        try:
            update_status(
                cid,
                selected_status,
                analyst,
            )
            st.success("Case status saved.")
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(str(exc))

    st.divider()

    note = st.text_area(
        "Add analyst observation",
        height=125,
        max_chars=4000,
        placeholder=(
            "Record the evidence and review decisions..."
        ),
    )

    if st.button("Save Analyst Note"):
        try:
            add_note(
                cid,
                note,
                analyst,
            )
            st.success("Note saved.")
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(str(exc))

    st.subheader("Analyst Notes")

    if record["notes"]:
        for item in reversed(record["notes"]):
            with st.expander(
                str(item.get("timestamp") or "Unknown time")
            ):
                st.caption(
                    str(item.get("actor") or "Unknown")
                )
                st.code(
                    str(item.get("text") or ""),
                    language=None,
                )
    else:
        st.info("No analyst notes recorded.")

    st.subheader("Case Activity")

    if record["history"]:
        st.dataframe(
            list(reversed(record["history"])),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No status or note actions recorded.")

    st.caption(
        "Analyst labels are not authenticated identities. "
        "This local history is not tamper-proof."
    )


def render_intelligence(reports):
    st.markdown("## 🌐 Threat Intelligence")

    report = select_report(reports, "intelligence")

    if report is None:
        return

    feed = report.get("feed_context") or {}
    iocs = get_iocs(report)

    a, b, c = st.columns(3)
    a.metric("Email URLs", iocs.get("total_urls", 0))
    b.metric("Email Domains", iocs.get("total_domains", 0))
    c.metric("Priority", get_priority(report))

    st.subheader("Local Feed Correlation")
    st.json(feed)

    st.caption(
        "Feed matches provide leads, not a confirmed "
        "malicious classification. No URL is visited."
    )


def render_evidence_exports(reports):
    st.markdown("## 📁 Evidence & Analyst Exports")

    report = select_report(reports, "export")

    if report is None:
        return

    cid = report["case_id"]

    st.subheader("Evidence Manifest")

    evidence = report.get("evidence") or []

    if evidence:
        st.dataframe(
            evidence,
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No evidence manifest items available.")

    try:
        record = load_case(cid)
        document = build_analyst_export(
            report,
            record,
        )
    except (ValueError, OSError, TypeError, KeyError) as exc:
        st.error(f"Export error: {exc}")
        return

    st.divider()

    st.subheader("Analyst Report")

    st.caption(
        "Exports may contain sensitive analyst notes, "
        "email metadata and evidence hashes."
    )

    one, two = st.columns(2)

    with one:
        st.download_button(
            "↓ Download TXT Report",
            data=export_text(document).encode("utf-8"),
            file_name=f"phishscope_{cid}.txt",
            mime="text/plain",
        )

    with two:
        st.download_button(
            "↓ Download JSON Report",
            data=export_json_bytes(document),
            file_name=f"phishscope_{cid}.json",
            mime="application/json",
        )

    st.subheader("Investigation Timeline")

    for event in document.get("timeline") or []:
        with st.expander(
            f"{event.get('timestamp') or 'Unknown'} "
            f"· {event.get('type') or 'event'}"
        ):
            st.code(
                str(event.get("description") or ""),
                language=None,
            )
            if "note" in event:
                st.code(
                    str(event["note"]),
                    language=None,
                )


def main():
    st.markdown(CSS, unsafe_allow_html=True)

    view, analyst = render_sidebar()

    st.markdown(
        '<div class="ps-header">'
        '<div>'
        '<div class="ps-kicker">'
        'Security Operations / Investigation Console'
        '</div>'
        '<div class="ps-brand">'
        'PHISH<span>SCOPE</span>'
        '</div>'
        '<div class="ps-muted">'
        'Defensive Phishing Intelligence Platform'
        '</div>'
        '</div>'
        '<div class="ps-pill">● LOCAL SOC · EMERALD EDITION</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    reports, errors = load_reports("reports")

    if errors:
        with st.expander(
            f"Report warnings ({len(errors)})"
        ):
            for error in errors:
                st.warning(error)

    if not reports:
        st.info(
            "No reports found. Generate an investigation "
            "using main.py to populate the dashboard."
        )
        return

    if view == "Overview":
        render_overview(reports)
    elif view == "Investigations":
        render_investigations(reports)
    elif view == "Case Management":
        render_case_management(reports, analyst)
    elif view == "Threat Intelligence":
        render_intelligence(reports)
    elif view == "Evidence & Export":
        render_evidence_exports(reports)


if __name__ == "__main__":
    main()
