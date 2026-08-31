"""Cryptographic data integrity verification using HMAC-SHA256.

Pure Python 3 standard library: hashlib, hmac, json, os, secrets, sqlite3.
"""

import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple

from zrevixdb.audit import log_audit_event
from zrevixdb.auth import require_role
from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import get_db_connection

DEFAULT_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".zrevix_secret.key",
)


def get_or_create_hmac_secret(key_file: Optional[str] = None) -> bytes:
    """Retrieve or securely generate the server-side HMAC secret key."""
    path = key_file or DEFAULT_KEY_FILE
    if os.path.exists(path):
        with open(path, "rb") as f:
            secret = f.read().strip()
            if secret:
                return secret

    # Generate a cryptographically strong 256-bit secret key
    secret = secrets.token_bytes(32)
    try:
        with open(path, "wb") as f:
            f.write(secret)
    except Exception as e:
        # If unable to write to disk, use in-memory secret
        print(f"[WARN] Unable to persist secret key file: {e}")
    return secret


def compute_version_hmac(
    record_id: str,
    version_num: int,
    data_json: str,
    created_at: str,
    secret: Optional[bytes] = None,
) -> str:
    """Compute HMAC-SHA256 signature for canonical version payload."""
    key = secret or get_or_create_hmac_secret()
    # Normalize JSON to ensure consistent canonical representation
    try:
        parsed = json.loads(data_json)
        canonical_json = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    except Exception:
        canonical_json = data_json

    message = f"record:{record_id}|version:{version_num}|created_at:{created_at}|data:{canonical_json}"
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_record(
    record_id: str,
    secret: Optional[bytes] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify cryptographic integrity of every version of a specific record."""
    key = secret or get_or_create_hmac_secret()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, version_num, data_json, checksum, created_at, commit_message
        FROM record_versions
        WHERE record_id = ?
        ORDER BY version_num ASC
        """,
        (record_id,),
    )
    versions = cursor.fetchall()
    conn.close()

    if not versions:
        return {
            "record_id": record_id,
            "is_valid": True,
            "total_versions": 0,
            "anomalies": [],
            "message": "No versions found for record",
        }

    anomalies = []
    for v in versions:
        computed = compute_version_hmac(
            record_id=record_id,
            version_num=v["version_num"],
            data_json=v["data_json"],
            created_at=v["created_at"],
            secret=key,
        )

        stored = v["checksum"] or ""
        if not hmac.compare_digest(stored, computed):
            anomalies.append({
                "version_id": v["id"],
                "version_num": v["version_num"],
                "created_at": v["created_at"],
                "stored_checksum": stored,
                "expected_checksum": computed,
                "commit_message": v["commit_message"],
                "error": "Cryptographic checksum mismatch: version payload altered or corrupted",
            })

    is_valid = len(anomalies) == 0
    return {
        "record_id": record_id,
        "is_valid": is_valid,
        "total_versions": len(versions),
        "valid_versions": len(versions) - len(anomalies),
        "anomalies": anomalies,
    }


def verify_all(
    secret: Optional[bytes] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run cryptographic integrity checks across all records in the database."""
    key = secret or get_or_create_hmac_secret()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, collection, key, is_deleted, created_at FROM records ORDER BY collection, key")
    records = cursor.fetchall()
    conn.close()

    total_records = len(records)
    valid_records = 0
    compromised_records = 0
    total_versions_scanned = 0
    record_results = []
    all_anomalies = []

    for rec in records:
        rec_id = rec["id"]
        res = verify_record(rec_id, secret=key, db_path=db_path)
        total_versions_scanned += res["total_versions"]

        rec_entry = {
            "record_id": rec_id,
            "collection": rec["collection"],
            "key": rec["key"],
            "is_deleted": bool(rec["is_deleted"]),
            "is_valid": res["is_valid"],
            "total_versions": res["total_versions"],
            "anomalies": res["anomalies"],
        }
        record_results.append(rec_entry)

        if res["is_valid"]:
            valid_records += 1
        else:
            compromised_records += 1
            for anomaly in res["anomalies"]:
                all_anomalies.append({
                    "record_id": rec_id,
                    "collection": rec["collection"],
                    "key": rec["key"],
                    **anomaly,
                })

    is_healthy = compromised_records == 0
    return {
        "is_healthy": is_healthy,
        "scanned_records": total_records,
        "valid_records": valid_records,
        "compromised_records": compromised_records,
        "total_versions_scanned": total_versions_scanned,
        "records": record_results,
        "anomalies": all_anomalies,
    }


def register_integrity_routes(router: Router, db_path: Optional[str] = None):
    """Register integrity verification API routes."""

    @router.get("/api/integrity/check")
    @require_role("Admin", "Manager", "Auditor", db_path=db_path)
    def integrity_check_route(req: Request) -> Response:
        record_id = req.query.get("record_id", [None])[0]
        if record_id:
            result = verify_record(record_id, db_path=db_path)
            return Response.json(result)

        summary = verify_all(db_path=db_path)
        log_audit_event(
            event_type="INTEGRITY_AUDIT_RUN",
            actor_id=req.user.get("id"),
            target_type="system",
            target_id="all_records",
            details={
                "is_healthy": summary["is_healthy"],
                "scanned_records": summary["scanned_records"],
                "compromised_records": summary["compromised_records"],
            },
            db_path=db_path,
        )
        return Response.json(summary)
