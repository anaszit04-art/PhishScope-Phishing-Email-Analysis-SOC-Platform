
"""
PhishScope — Case Timeline & Analyst Export

A separate Streamlit page that adds analyst reporting
without modifying the main SOC dashboard.

Downloads are generated in memory.
The original case report and evidence are untouched.
"""

import streamlit as st

from src.dashboard_data import load_reports
from src.case_manager import load_case
from src.case_export import (
    build_analyst_export,
    export_json_bytes,
    export_text
)


st.set_page_config(
    page_title="PhishScope Case Export",
    page_icon="📋",
    layout="wide"
)


def render_timeline(events):
    """Display timeline entries safely as text."""
    if not events:
        st.info("No timeline events available.")
        return

    for event in events:
        timestamp = event.get("timestamp") or "Unknown time"
        event_type = event.get("type", "unknown")

        with st.expander(
            f"{timestamp} — {event_type}",
            expanded=False
        ):
            st.write("Actor")
            st.code(
                str(event.get("actor", "Unknown")),
                language=None
            )

            st.write("Description")
            st.code(
                str(event.get("description", "")),
                language=None
            )

            if "note" in event:
                st.write("Analyst note")
                st.code(
                    str(event["note"]),
                    language=None
                )


def main():
    st.title("📋 Case Timeline & Analyst Export")

    st.caption(
        "Generate a chronological case summary "
        "without changing investigation evidence."
    )

    reports, errors = load_reports("reports")

    if errors:
        with st.expander(
            f"Loading warnings ({len(errors)})"
        ):
            for error in errors:
                st.text(error)

    if not reports:
        st.warning(
            "No investigation reports found."
        )
        st.stop()

    st.sidebar.header("Case export")

    search = st.sidebar.text_input(
        "Search case ID or subject"
    )

    filtered = []

    for report in reports:
        email = report.get("email_analysis") or {}
        subject = (
            (email.get("headers") or {}).get(
                "subject", ""
            )
        )

        search_text = (
            str(report.get("case_id", ""))
            + " "
            + str(subject)
        ).lower()

        if search.lower() in search_text:
            filtered.append(report)

    if not filtered:
        st.info("No matching investigations.")
        st.stop()

    labels = {
        item["_dashboard_filename"]: (
            f"{str(item['case_id'])[:8]} "
            f"| {str((item.get('email_analysis') or {}).get('headers', {}).get('subject', ''))[:60]}"
        )
        for item in filtered
    }

    selection = st.selectbox(
        "Select a case",
        options=list(labels),
        format_func=lambda name: labels[name]
    )

    report = next(
        item
        for item in filtered
        if item["_dashboard_filename"] == selection
    )

    case_id = report["case_id"]

    try:
        case_record = load_case(case_id)

        document = build_analyst_export(
            report,
            case_record
        )

    except (
        ValueError,
        OSError,
        KeyError,
        TypeError
    ) as exc:
        st.error(
            f"Cannot prepare this case export: {exc}"
        )
        st.stop()

    risk = document["risk_assessment"]
    email = document["email"]

    st.subheader("Selected case")

    st.write("Case ID")
    st.code(case_id, language=None)

    a, b, c, d = st.columns(4)

    a.metric(
        "Case status",
        document["case_status"]
    )

    b.metric(
        "Risk score",
        (
            f"{risk['score']}/100"
            if risk["score"] is not None
            else "N/A"
        )
    )

    c.metric(
        "Advanced findings",
        len(document["advanced_findings"])
    )

    d.metric(
        "Timeline events",
        len(document["timeline"])
    )

    st.write("Email subject")
    st.code(
        str(email.get("subject") or ""),
        language=None
    )

    st.subheader("Chronological investigation timeline")

    render_timeline(document["timeline"])

    st.divider()

    st.subheader("Analyst report export")

    st.caption(
        "Exports may contain sensitive analyst notes, "
        "sender addresses, evidence hashes, and case "
        "metadata. Keep downloaded files private."
    )

    text_report = export_text(document)
    json_report = export_json_bytes(document)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="Download analyst report (.txt)",
            data=text_report.encode("utf-8"),
            file_name=f"phishscope_{case_id}.txt",
            mime="text/plain",
            use_container_width=False
        )

    with col2:
        st.download_button(
            label="Download structured export (.json)",
            data=json_report,
            file_name=f"phishscope_{case_id}.json",
            mime="application/json",
            use_container_width=False
        )

    with st.expander("Preview analyst report"):
        st.code(
            text_report,
            language=None
        )

    st.info(
        "These exports are analyst summaries. "
        "Neither the original .eml nor the "
        "unified investigation JSON is modified."
    )


if __name__ == "__main__":
    main()
