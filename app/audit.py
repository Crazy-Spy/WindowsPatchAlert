"""Content normalization, SHA-256 hashing, and persistent field-level audit trail."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_text(value: Any) -> str:
    """Normalize text for deterministic comparison and hashing."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).strip()
    # Collapse repeated whitespace
    return re.sub(r"\s+", " ", text)


def calculate_content_hash(payload: Any) -> str:
    """
    Normalize a string, dict, or list payload and calculate its deterministic SHA-256 hex digest.
    """
    if isinstance(payload, (dict, list)):
        def _clean(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {str(k): _clean(v) for k, v in sorted(obj.items()) if k not in ("content_hash", "last_checked_at", "id")}
            if isinstance(obj, list):
                return [_clean(i) for i in obj]
            return normalize_text(obj)

        canonical = json.dumps(_clean(payload), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    else:
        canonical = normalize_text(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_field_diffs(
    old_record: Optional[Mapping[str, Any]],
    new_record: Mapping[str, Any],
    tracked_fields: Sequence[str],
) -> list[dict[str, str]]:
    """
    Compare tracked fields between an existing record and an incoming normalized record.
    Returns a list of field diff dicts: {field_name, old_value, new_value, change_type}.
    """
    diffs: list[dict[str, str]] = []
    if old_record is None:
        for field in tracked_fields:
            new_val = normalize_text(new_record.get(field))
            if new_val:
                diffs.append(
                    {
                        "field_name": field,
                        "old_value": "",
                        "new_value": new_val,
                        "change_type": "CREATED",
                    }
                )
        return diffs

    for field in tracked_fields:
        old_val = normalize_text(old_record.get(field))
        new_val = normalize_text(new_record.get(field))
        if old_val != new_val:
            change_type = "STATUS_CHANGED" if "status" in field.lower() else "UPDATED"
            diffs.append(
                {
                    "field_name": field,
                    "old_value": old_val,
                    "new_value": new_val,
                    "change_type": change_type,
                }
            )
    return diffs


def record_entity_changes(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    kb_number: Optional[str],
    old_record: Optional[Mapping[str, Any]],
    new_record: Mapping[str, Any],
    tracked_fields: Sequence[str],
    source_url: Optional[str] = None,
    is_demo: bool = False,
    detected_at: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """
    Calculate the SHA-256 content hash for the tracked fields, compare with old_record,
    and persist any field-level differences to the change_log table.
    Returns (content_hash, recorded_changes).
    """
    hash_payload = {f: new_record.get(f) for f in tracked_fields}
    content_hash = calculate_content_hash(hash_payload)
    timestamp = detected_at or utc_now_iso()

    # Fast path: if old_record exists and has the exact same content_hash, verify no fields changed
    if old_record is not None and old_record.get("content_hash") == content_hash:
        return content_hash, []

    diffs = compute_field_diffs(old_record, new_record, tracked_fields)
    recorded: list[dict[str, Any]] = []

    if old_record is None and diffs:
        # Record a single concise creation audit entry plus key status fields to avoid cluttering on initial insert,
        # OR record all tracked fields if it's an update. For CREATED, record summary field + status.
        primary_fields = [d for d in diffs if d["field_name"] in ("title", "health_status", "status", "severity", "has_kir", "is_oob")]
        target_diffs = primary_fields if primary_fields else diffs[:2]
    else:
        target_diffs = diffs

    for diff in target_diffs:
        cur = conn.execute(
            """
            INSERT INTO change_log (
                entity_type, entity_id, kb_number, field_name,
                old_value, new_value, change_type, content_hash,
                source_url, is_demo, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_type,
                entity_id,
                kb_number,
                diff["field_name"],
                diff["old_value"],
                diff["new_value"],
                diff["change_type"],
                content_hash,
                source_url,
                1 if is_demo else 0,
                timestamp,
            ),
        )
        entry = {
            "id": cur.lastrowid,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "kb_number": kb_number,
            "field_name": diff["field_name"],
            "old_value": diff["old_value"],
            "new_value": diff["new_value"],
            "change_type": diff["change_type"],
            "content_hash": content_hash,
            "source_url": source_url,
            "is_demo": is_demo,
            "detected_at": timestamp,
        }
        recorded.append(entry)

    return content_hash, recorded

