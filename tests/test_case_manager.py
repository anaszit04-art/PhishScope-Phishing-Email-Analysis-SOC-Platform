
import json
import os
import uuid

import pytest

from src.case_manager import (
    add_note,
    load_case,
    update_status,
    validate_actor,
    validate_case_id,
    validate_note,
)


def make_id():
    return str(uuid.uuid4())


def test_new_case_defaults(tmp_path):
    case_id = make_id()
    result = load_case(case_id, tmp_path)

    assert result["status"] == "open"
    assert result["notes"] == []
    assert result["history"] == []


def test_change_case_status(tmp_path):
    case_id = make_id()

    result = update_status(
        case_id,
        "in_review",
        "Analyst",
        tmp_path
    )

    assert result["status"] == "in_review"

    loaded = load_case(case_id, tmp_path)

    assert loaded["status"] == "in_review"


def test_invalid_case_status(tmp_path):
    with pytest.raises(ValueError):
        update_status(
            make_id(),
            "deleted",
            "Analyst",
            tmp_path
        )


def test_add_analyst_note(tmp_path):
    case_id = make_id()

    result = add_note(
        case_id,
        "Synthetic phishing email requires review.",
        "SOC Analyst",
        tmp_path
    )

    assert len(result["notes"]) == 1
    assert result["notes"][0]["actor"] == "SOC Analyst"


def test_history_records_actions(tmp_path):
    case_id = make_id()

    update_status(
        case_id,
        "in_review",
        "Analyst",
        tmp_path
    )

    add_note(
        case_id,
        "Header analysis complete.",
        "Analyst",
        tmp_path
    )

    result = load_case(case_id, tmp_path)

    assert len(result["history"]) == 2
    assert result["history"][0]["action"] == "status_change"
    assert result["history"][1]["action"] == "note_added"


def test_duplicate_status_not_recorded(tmp_path):
    case_id = make_id()

    update_status(
        case_id,
        "open",
        "Analyst",
        tmp_path
    )

    result = load_case(case_id, tmp_path)

    assert result["history"] == []


def test_invalid_case_id():
    with pytest.raises(ValueError):
        validate_case_id("../../reports")


def test_empty_note_rejected():
    with pytest.raises(ValueError):
        validate_note("   ")


def test_large_note_rejected():
    with pytest.raises(ValueError):
        validate_note("A" * 4001)


def test_invalid_actor():
    with pytest.raises(ValueError):
        validate_actor("")


def test_case_metadata_private(tmp_path):
    case_id = make_id()

    add_note(
        case_id,
        "Permission check",
        "Analyst",
        tmp_path
    )

    path = tmp_path / f"{case_id}.json"

    permissions = os.stat(path).st_mode & 0o777

    assert permissions == 0o600


def test_independent_cases(tmp_path):
    first = make_id()
    second = make_id()

    add_note(
        first,
        "First case",
        "Analyst",
        tmp_path
    )

    add_note(
        second,
        "Second case",
        "Analyst",
        tmp_path
    )

    first_record = load_case(first, tmp_path)
    second_record = load_case(second, tmp_path)

    assert first_record["notes"][0]["text"] == "First case"
    assert second_record["notes"][0]["text"] == "Second case"
