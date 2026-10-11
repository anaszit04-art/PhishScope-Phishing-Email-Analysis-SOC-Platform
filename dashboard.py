
"""
PhishScope — SOC Dashboard with Case Management

Local interface for phishing investigations.

Original evidence and generated investigation reports
remain read-only. Analyst metadata is saved separately.

Run with:
python -m streamlit run dashboard.py \
    --server.address 127.0.0.1 \
    --server.port 8501 \
    --browser.gatherUsageStats false
"""

import streamlit as st

from src.dashboard_data import (
    get_risk,
    load_reports,
    summarize_all,
    summarize_case,
)

from src.case_manager import (
    VALID_STATUSES,
    add_note,
    load_case,
    update_status,
)


st.set_page_config(
    page_title="PhishScope SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def safe_text(value):
    """Show potentially suspicious text as inert text."""
    st.code(str(value or ""), language=None)


def show_overview(reports, case_records):
    summary = summarize_all(reports)

    st.subheader("Investigation overview")

    a, b, c, d = st.columns(4)

    a.metric("Total cases", summary["total_cases"])
    b.metric("Scored cases", summary["scored_cases"])
    c.metric(
        "Average score",
        summary["average_score"]
        if summary["average_score"] is not None
        else "N/A"
    )

    d.metric(
        "Cases in review",
        sum(
            record["status"] == "in_review"
            for record in case_records.values()
        )
    )

    rows = []

    for report in reports:
        row = summarize_case(report)
        case_id = report["case_id"]

        row["Case status"] = case_records[
            case_id
        ]["status"]

        rows.append(row)

    st.subheader("Investigation queue")

    st.dataframe(
        rows,
        width="stretch",
        hide_index=True
    )

    st.caption(
        "Scores are heuristic review priorities, "
        "not confirmed phishing probabilities."
    )


def show_email_tab(report):
    email = report.get("email_analysis") or {}
    headers = email.get("headers") or {}
    iocs = email.get("iocs") or {}

    st.subheader("Email information")

    st.write("Subject")
    safe_text(headers.get("subject"))

    st.write("Sender")
    safe_text(headers.get("sender_address"))

    st.write("Reply-To")
    safe_text(headers.get("reply_to_address"))

    st.write(
        "Attachments:",
        len(email.get("attachments") or [])
    )

    st.subheader("Extracted URLs")

    details = iocs.get("url_details") or []

    if not details:
        st.info("No URLs extracted.")

    for item in details:
        if isinstance(item, dict):
            safe_text(item.get("url"))

    st.caption(
        "Displayed URLs may include text-only URLs "
        "and actual HTML link destinations."
    )


def show_detection_tab(report):
    advanced = report.get("advanced_detection") or {}
    risk = report.get("risk_assessment") or {}

    st.subheader("Advanced findings")

    findings = advanced.get("findings") or []

    if not findings:
        st.info("No advanced findings recorded.")

    for finding in findings:
        label = (
            f"{finding.get('rule_id', 'Unknown')} — "
            f"{finding.get('description', '')}"
        )

        with st.expander(label):
            st.write(
                "Severity:",
                finding.get("severity", "unknown")
            )
            st.json(finding.get("evidence") or {})

    st.subheader("Risk assessment")

    score = get_risk(report)

    st.metric(
        "Heuristic score",
        f"{score}/100" if score is not None else "N/A"
    )

    if score is not None:
        st.progress(float(score) / 100)

    st.write(
        "Review priority:",
        risk.get("review_priority", "not_assessed")
    )

    st.write(
        "Verdict:",
        risk.get("verdict", "not_determined")
    )

    st.subheader("Scoring contributions")

    for item in risk.get("contributions") or []:
        st.write(
            f"+{item.get('points', 0)} — "
            f"{item.get('identifier', '')}"
        )
        st.caption(item.get("reason", ""))

    with st.expander("Risk limitations"):
        for limitation in risk.get("limitations") or []:
            st.write(limitation)


def show_intelligence_tab(report):
    feed = report.get("feed_context") or {}

    if not feed:
        st.info("No local intelligence feed used.")
        return

    st.subheader("Threat intelligence")

    st.write(
        "Snapshot downloaded:",
        feed.get("feed_download_time", "unknown")
    )

    st.write(
        "Recorded feed hash verified:",
        (feed.get("feed_integrity") or {}).get(
            "verified"
        )
    )

    counts = feed.get("match_counts") or {}

    a, b, c = st.columns(3)

    a.metric(
        "Exact URL",
        counts.get("exact_url", 0)
    )
    b.metric(
        "Normalized URL",
        counts.get("normalized_url", 0)
    )
    c.metric(
        "Hostname",
        counts.get("hostname", 0)
    )

    st.subheader("IOC correlations")

    for item in feed.get("findings") or []:
        st.write(
            "Match:",
            item.get("match_type", "unknown")
        )
        safe_text(item.get("url"))

    st.caption(
        "Hostname matches are weaker indicators. "
        "No match does not mean the URL is safe."
    )


def show_mitre_tab(report):
    mitre = report.get("mitre_analysis") or {}
    redirect = report.get("redirect_analysis") or {}

    st.subheader("ATT&CK candidates")

    techniques = mitre.get("technique_candidates") or []

    if not techniques:
        st.info("No ATT&CK candidates.")

    for item in techniques:
        st.write(
            item.get("technique_id", ""),
            "—",
            item.get("technique_name", "")
        )
        st.caption(
            "Status: " + str(
                item.get("status", "candidate")
            )
        )

    st.caption(
        "Candidate ATT&CK mappings do not prove "
        "execution or compromise."
    )

    st.subheader("Recorded redirects")

    if not redirect:
        st.info("No redirect evidence supplied.")
        return

    st.write(
        "Total hops:",
        redirect.get("total_hops", 0)
    )

    st.write(
        "Redirect count:",
        redirect.get("redirect_count", 0)
    )

    st.write("Initial URL")
    safe_text(redirect.get("initial_url"))

    st.write("Final URL")
    safe_text(redirect.get("final_url"))


def show_evidence_tab(report):
    st.subheader("Evidence manifest")

    evidence = report.get("evidence") or []

    if not evidence:
        st.info("No evidence manifest.")

    for item in evidence:
        st.write(
            "Type:",
            item.get("type", "")
        )

        st.write(
            "Filename:",
            item.get("filename", "")
        )

        st.write(
            "Size:",
            item.get("size_bytes", 0),
            "bytes"
        )

        st.write("SHA-256")
        safe_text(item.get("sha256"))
        st.divider()

    st.caption(
        "The dashboard does not modify or rehash "
        "the original evidence files."
    )


def show_case_management(case_id, actor):
    """
    Manage workflow information separately from
    immutable investigation evidence.
    """
    st.subheader("SOC Case Management")

    try:
        record = load_case(case_id)
    except (OSError, ValueError) as exc:
        st.error(f"Cannot read case metadata: {exc}")
        return

    st.write("Current status:", record["status"])

    with st.form(
        key=f"status_form_{case_id}"
    ):
        selected_status = st.selectbox(
            "Investigation status",
            VALID_STATUSES,
            index=VALID_STATUSES.index(
                record["status"]
            )
        )

        submitted = st.form_submit_button(
            "Save status"
        )

    if submitted:
        try:
            update_status(
                case_id,
                selected_status,
                actor
            )
        except (OSError, ValueError) as exc:
            st.error(f"Status update failed: {exc}")
        else:
            st.success("Case status saved.")
            st.rerun()

    st.subheader("Add analyst note")

    with st.form(
        key=f"note_form_{case_id}",
        clear_on_submit=True
    ):
        note = st.text_area(
            "Investigation note",
            max_chars=4000,
            placeholder=(
                "Describe the evidence or next action..."
            )
        )

        note_submitted = st.form_submit_button(
            "Save note"
        )

    if note_submitted:
        try:
            add_note(case_id, note, actor)
        except (OSError, ValueError) as exc:
            st.error(f"Could not save note: {exc}")
        else:
            st.success("Analyst note saved.")
            st.rerun()

    st.subheader("Analyst notes")

    if not record["notes"]:
        st.info("No notes recorded yet.")

    for entry in reversed(record["notes"]):
        with st.expander(
            f"{entry['timestamp']} — {entry['actor']}"
        ):
            safe_text(entry["text"])

    st.subheader("Case action history")

    if not record["history"]:
        st.info("No actions recorded yet.")
    else:
        st.dataframe(
            list(reversed(record["history"])),
            width="stretch",
            hide_index=True
        )

    st.caption(
        "Audit history is application-level metadata, "
        "not a tamper-proof audit trail. "
        "Analyst labels are not authenticated identities."
    )


def show_selected_case(report, actor):
    case_id = report["case_id"]

    email = report.get("email_analysis") or {}
    headers = email.get("headers") or {}
    advanced = report.get("advanced_detection") or {}
    iocs = email.get("iocs") or {}
    risk = report.get("risk_assessment") or {}

    st.subheader("Selected investigation")

    st.write("Case ID")
    safe_text(case_id)

    st.write(
        "Generated:",
        report.get("generated_at", "")
    )

    st.write("Subject")
    safe_text(headers.get("subject"))

    score = get_risk(report)

    a, b, c, d = st.columns(4)

    a.metric(
        "Risk score",
        f"{score}/100" if score is not None else "N/A"
    )
    b.metric(
        "Priority",
        risk.get("review_priority", "not_assessed")
    )
    c.metric(
        "Findings",
        advanced.get("total_findings", 0)
    )
    d.metric(
        "URLs",
        iocs.get("total_urls", 0)
    )

    tabs = st.tabs([
        "Case management",
        "Email",
        "Detections",
        "Threat intelligence",
        "ATT&CK & redirects",
        "Evidence",
        "Raw report"
    ])

    with tabs[0]:
        show_case_management(case_id, actor)

    with tabs[1]:
        show_email_tab(report)

    with tabs[2]:
        show_detection_tab(report)

    with tabs[3]:
        show_intelligence_tab(report)

    with tabs[4]:
        show_mitre_tab(report)

    with tabs[5]:
        show_evidence_tab(report)

    with tabs[6]:
        clean_report = {
            key: value
            for key, value in report.items()
            if not key.startswith("_dashboard_")
        }
        st.json(clean_report, expanded=False)


def main():
    st.title("🛡️ PhishScope SOC Dashboard")

    st.caption(
        "Local phishing investigation and "
        "analyst case-management interface"
    )

    with st.sidebar:
        st.header("SOC Controls")

        actor = st.text_input(
            "Analyst label",
            value="SOC Analyst",
            max_chars=80
        )

        if st.button("Refresh reports"):
            st.rerun()

        st.divider()

        search = st.text_input(
            "Search case ID or subject",
            value=""
        )

        priority_filter = st.selectbox(
            "Review priority",
            [
                "all",
                "high",
                "elevated",
                "routine",
                "low",
                "not_assessed"
            ]
        )

        status_filter = st.selectbox(
            "Case status",
            [
                "all",
                *VALID_STATUSES
            ]
        )

        st.divider()

        st.warning(
            "Use only on your trusted Kali VM. "
            "The interface has no user authentication "
            "and can display sensitive case data."
        )

    reports, errors = load_reports("reports")

    if errors:
        with st.expander("Report loading warnings"):
            for error in errors:
                st.text(error)

    if not reports:
        st.warning(
            "No case reports found in reports/."
        )
        st.stop()

    records = {}

    usable_reports = []

    for report in reports:
        try:
            case_id = report["case_id"]
            records[case_id] = load_case(case_id)
            usable_reports.append(report)
        except (ValueError, OSError) as exc:
            st.warning(
                f"Cannot load case management metadata: "
                f"{exc}"
            )

    if not usable_reports:
        st.warning("No valid case records.")
        st.stop()

    filtered = []

    for report in usable_reports:
        case_id = report["case_id"]
        row = summarize_case(report)

        text = (
            case_id + " " + str(row["Subject"])
        ).lower()

        if search.lower() not in text:
            continue

        if (
            priority_filter != "all"
            and row["Priority"] != priority_filter
        ):
            continue

        if (
            status_filter != "all"
            and records[case_id]["status"] != status_filter
        ):
            continue

        filtered.append(report)

    show_overview(usable_reports, records)

    st.divider()

    st.subheader("Filtered cases")

    st.write(
        f"{len(filtered)} of "
        f"{len(usable_reports)} investigations match."
    )

    if not filtered:
        st.info("No matching investigations.")
        st.stop()

    labels = {
        report["_dashboard_filename"]: (
            f"{str(report.get('case_id', ''))[:8]} "
            f"| {str(summarize_case(report)['Subject'])[:55]}"
        )
        for report in filtered
    }

    selected = st.selectbox(
        "Select an investigation",
        list(labels),
        format_func=lambda name: labels[name]
    )

    report = next(
        item
        for item in filtered
        if item["_dashboard_filename"] == selected
    )

    show_selected_case(report, actor)


if __name__ == "__main__":
    main()
