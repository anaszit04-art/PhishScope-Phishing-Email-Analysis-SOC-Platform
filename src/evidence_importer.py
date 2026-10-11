
import argparse
import hashlib
import json
import os
import shutil
import stat
import uuid

from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path


MAX_EMAIL_SIZE = 10 * 1024 * 1024


def hash_file(path):
    """Calculate SHA-256 without modifying the file."""
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def validate_email(path):
    """Perform basic validation of an .eml file."""

    path = Path(path)

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported")

    if not path.is_file() or path.is_symlink():
        raise ValueError("Source must be a regular, non-symlink file")

    size = path.stat().st_size

    if size == 0 or size > MAX_EMAIL_SIZE:
        raise ValueError("Email must be between 1 byte and 10 MB")

    with path.open("rb") as handle:
        message = BytesParser(
            policy=policy.default
        ).parse(handle)

    if not any(
        message.get(name)
        for name in ("From", "To", "Date", "Subject", "Message-ID")
    ):
        raise ValueError(
            "Input does not appear to contain email headers"
        )

    return {
        "size_bytes": size,
        "sha256": hash_file(path),
        "subject": str(message.get("Subject", "")),
        "has_defects": bool(message.defects)
    }


def import_email(source, source_description,
                 evidence_root="data/evidence"):
    """
    Import a working copy of a raw email.

    The original source file is not modified.
    """

    source = Path(source)
    original_info = validate_email(source)

    case_id = str(uuid.uuid4())
    root = Path(evidence_root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)

    case_dir = root / f"case_{case_id}"
    case_dir.mkdir(mode=0o700)

    destination = case_dir / "original.eml"

    try:
        # Create a private evidence copy without overwriting.
        with source.open("rb") as src, destination.open("xb") as dst:
            os.chmod(destination, 0o600)
            shutil.copyfileobj(src, dst)

        copied_hash = hash_file(destination)
        source_hash_after = hash_file(source)

        if (
            copied_hash != original_info["sha256"]
            or source_hash_after != original_info["sha256"]
        ):
            raise RuntimeError(
                "Evidence hash changed during acquisition"
            )

        # Remove write permissions from the evidence copy.
        destination.chmod(stat.S_IRUSR)

        metadata = {
            "case_id": case_id,
            "acquired_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "source_description": source_description,
            "original_filename": source.name,
            "stored_filename": "original.eml",
            "size_bytes": original_info["size_bytes"],
            "sha256": copied_hash,
            "hash_algorithm": "SHA-256",
            "email_parse_defects": original_info["has_defects"],
            "evidence_type": "rfc5322_email",
            "note": (
                "Original input was not intentionally modified. "
                "This is a working evidence copy."
            )
        }

        metadata_path = case_dir / "acquisition.json"

        fd = os.open(
            metadata_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)

    except Exception:
        shutil.rmtree(case_dir)
        raise

    return {
        "case_id": case_id,
        "evidence_path": str(destination),
        "metadata_path": str(metadata_path),
        "sha256": copied_hash
    }


def main():
    parser = argparse.ArgumentParser(
        description="PhishScope Evidence Importer"
    )

    parser.add_argument(
        "--email",
        required=True,
        help="Local raw .eml file"
    )

    parser.add_argument(
        "--source",
        required=True,
        help="Evidence origin description"
    )

    args = parser.parse_args()

    result = import_email(
        args.email,
        args.source
    )

    print("[+] Evidence imported")
    print("[+] Case ID:", result["case_id"])
    print("[+] SHA-256:", result["sha256"])
    print("[+] Evidence:", result["evidence_path"])
    print("[+] Metadata:", result["metadata_path"])


if __name__ == "__main__":
    main()
