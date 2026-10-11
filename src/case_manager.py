
"""
PhishScope — SOC Case Management Backend

Stores analyst workflow information separately from
the original email evidence and investigation reports.

Features:
- Case status tracking
- Analyst notes
- Append-only application-level event history
- UTC timestamps
- Restricted file permissions
- Atomic replacement of case metadata

Note: This is a local single-user workflow system,
not a tamper-proof or multi-user audit database.
"""

import json
import os
import tempfile
import uuid

from datetime import datetime, timezone
from pathlib import Path


CASE_ROOT = Path("data/case_management/cases")

VALID_STATUSES = (
    "open",
    "in_review",
    "closed"
)

MAX_NOTE_LENGTH = 4000
MAX_ACTOR_LENGTH = 80


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_case_id(case_id):
    """Accept only canonical UUID case identifiers."""
    try:
        parsed = uuid.UUID(str(case_id))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("Invalid case ID") from None

    if str(parsed) != str(case_id):
        raise ValueError("Case ID must be a canonical UUID")

    return str(parsed)


def validate_actor(actor):
    """Validate the analyst label."""
    if not isinstance(actor, str):
        raise ValueError("Analyst must be text")

    actor = actor.strip()

    if not actor or len(actor) > MAX_ACTOR_LENGTH:
        raise ValueError(
            "Analyst must contain 1–80 characters"
        )

    if any(ord(char) < 32 for char in actor):
        raise ValueError("Invalid analyst characters")

    return actor


def validate_note(note):
    """Validate a new analyst note."""
    if not isinstance(note, str):
        raise ValueError("Note must be text")

    note = note.strip()

    if not note or len(note) > MAX_NOTE_LENGTH:
        raise ValueError(
            "Note must contain 1–4000 characters"
        )

    return note


def case_path(case_id, root=CASE_ROOT):
    case_id = validate_case_id(case_id)
    return Path(root) / f"{case_id}.json"


def new_case(case_id):
    """Create the default workflow record in memory."""
    case_id = validate_case_id(case_id)

    return {
        "case_id": case_id,
        "status": "open",
        "updated_at": None,
        "notes": [],
        "history": []
    }


def load_case(case_id, root=CASE_ROOT):
    """
    Load case metadata without modifying any files.

    A missing record means the investigation has not
    yet received analyst annotations.
    """
    path = case_path(case_id, root)

    if not path.exists():
        return new_case(case_id)

    if path.is_symlink():
        raise ValueError("Symlink case records are forbidden")

    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Case record exceeds 1 MB")

    with path.open("r", encoding="utf-8") as file:
        record = json.load(file)

    if not isinstance(record, dict):
        raise ValueError("Invalid case record")

    if record.get("case_id") != case_id:
        raise ValueError("Case ID mismatch")

    if record.get("status") not in VALID_STATUSES:
        raise ValueError("Invalid stored status")

    if not isinstance(record.get("notes"), list):
        raise ValueError("Invalid stored notes")

    if not isinstance(record.get("history"), list):
        raise ValueError("Invalid stored history")

    return record


def save_case(record, root=CASE_ROOT):
    """
    Save case metadata using a temporary file
    and atomic os.replace() on the same filesystem.

    Intended for one analyst process at a time.
    """
    case_id = validate_case_id(record["case_id"])

    directory = Path(root)
    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700
    )

    os.chmod(directory, 0o700)

    destination = case_path(case_id, directory)

    if destination.is_symlink():
        raise ValueError("Symlink case records are forbidden")

    temporary = None

    try:
        fd, temporary = tempfile.mkstemp(
            prefix=".case_",
            suffix=".tmp",
            dir=directory
        )

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:
            os.fchmod(file.fileno(), 0o600)

            json.dump(
                record,
                file,
                indent=2,
                ensure_ascii=False
            )

            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary, destination)

    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)

    return destination


def update_status(
    case_id,
    status,
    actor,
    root=CASE_ROOT
):
    """Change case status and record the action."""
    if status not in VALID_STATUSES:
        raise ValueError("Unknown case status")

    actor = validate_actor(actor)
    record = load_case(case_id, root)

    previous = record["status"]

    if previous == status:
        return record

    timestamp = utc_now()

    record["status"] = status
    record["updated_at"] = timestamp

    record["history"].append({
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "actor": actor,
        "action": "status_change",
        "previous": previous,
        "new": status
    })

    save_case(record, root)

    return record


def add_note(
    case_id,
    note,
    actor,
    root=CASE_ROOT
):
    """Add an analyst note and corresponding event."""
    actor = validate_actor(actor)
    note = validate_note(note)

    record = load_case(case_id, root)

    timestamp = utc_now()
    note_id = str(uuid.uuid4())

    record["notes"].append({
        "note_id": note_id,
        "timestamp": timestamp,
        "actor": actor,
        "text": note
    })

    record["history"].append({
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "actor": actor,
        "action": "note_added",
        "note_id": note_id
    })

    record["updated_at"] = timestamp

    save_case(record, root)

    return record
