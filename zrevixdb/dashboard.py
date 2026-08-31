"""Dashboard summary aggregation for the Enterprise Overview page.

Pulls real numbers from storage, integrity, and audit modules.
Pure Python 3 standard library: os, pathlib, sqlite3 (via storage helpers).
"""

import os
from typing import Any, Dict, Optional

from zrevixdb.audit import get_audit_log
from zrevixdb.auth import require_role
from zrevixdb.integrity import verify_all
from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import DEFAULT_DB_PATH, get_db_connection


def get_dashboard_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Aggregate real, live statistics for the Overview dashboard."""
    path = db_path or DEFAULT_DB_PATH

    conn = get_db_connection(path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM records WHERE is_deleted = 0")
    active_records = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM records")
    total_records = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM record_versions")
    total_versions = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM users")
    total_users = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM sessions")
    active_sessions = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(DISTINCT collection) as c FROM records")
    total_collections = cursor.fetchone()["c"]

    conn.close()

    # Storage size: real bytes on disk for the sqlite3 file (+ WAL/SHM siblings).
    storage_bytes = 0
    for suffix in ("", "-wal", "-shm"):
        candidate = path + suffix
        if os.path.isfile(candidate):
            storage_bytes += os.path.getsize(candidate)

    # Integrity scan (real cryptographic verification, not cached).
    integrity_summary = verify_all(db_path=path)
    if integrity_summary["scanned_records"] > 0:
        integrity_pct = round(
            100.0 * integrity_summary["valid_records"] / integrity_summary["scanned_records"], 1
        )
    else:
        integrity_pct = 100.0

    # Recent activity: last 8 audit log entries.
    recent_activity = get_audit_log(limit=8, db_path=path)

    health = "Healthy" if integrity_summary["is_healthy"] else "Anomalies Detected"

    return {
        "total_records": total_records,
        "active_records": active_records,
        "total_versions": total_versions,
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_collections": total_collections,
        "storage_bytes": storage_bytes,
        "storage_path": path,
        "integrity_pct": integrity_pct,
        "integrity_scanned": integrity_summary["scanned_records"],
        "integrity_valid": integrity_summary["valid_records"],
        "integrity_compromised": integrity_summary["compromised_records"],
        "system_health": health,
        "recent_activity": recent_activity,
    }


def register_dashboard_routes(router: Router, db_path: Optional[str] = None):
    """Register the dashboard summary endpoint (any authenticated role)."""

    @router.get("/api/dashboard/summary")
    @require_role("Admin", "Manager", "Auditor", "Viewer", db_path=db_path)
    def dashboard_summary_route(req: Request) -> Response:
        summary = get_dashboard_summary(db_path=db_path)
        return Response.json(summary)
