"""Enterprise Audit Trail module for recording and querying immutable operational history.

Pure Python 3 standard library: sqlite3, json, datetime.
"""

import datetime
import json
from typing import Any, Dict, List, Optional, Union

from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import get_db_connection


def log_action(
    user: Optional[Union[Dict[str, Any], int, str]] = None,
    action: Optional[str] = None,
    target_record_id: Optional[str] = None,
    target_type: str = "record",
    details: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
    # Backward/alternate keyword arguments support
    event_type: Optional[str] = None,
    actor_id: Optional[int] = None,
    target_id: Optional[str] = None,
    **kwargs: Any,
) -> int:
    """Write an immutable audit log entry into the audit_log table."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    effective_action = action or event_type or "UNKNOWN_ACTION"
    effective_target_id = target_record_id or target_id

    final_actor_id: Optional[int] = actor_id
    actor_username: Optional[str] = None

    if isinstance(user, dict):
        final_actor_id = user.get("id")
        actor_username = user.get("username")
    elif isinstance(user, int):
        final_actor_id = user
    elif isinstance(user, str):
        actor_username = user

    audit_details = dict(details or {})
    if actor_username and "actor_username" not in audit_details:
        audit_details["actor_username"] = actor_username

    details_json = json.dumps(audit_details, sort_keys=True)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO audit_log (event_type, actor_id, target_type, target_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (effective_action, final_actor_id, target_type, effective_target_id, details_json, now_iso),
        )
        audit_id = cursor.lastrowid
        conn.commit()
    except Exception as e:
        print(f"[AUDIT ERROR] Failed to write audit row: {e}")
        audit_id = -1
    finally:
        conn.close()

    actor_display = actor_username or (f"User#{final_actor_id}" if final_actor_id else "Anonymous/System")
    print(f"[AUDIT] {now_iso} | {actor_display} | {effective_action} | {target_type}:{effective_target_id or 'none'}")

    return audit_id


# Alias for backward compatibility
log_audit_event = log_action


def get_audit_log(
    user: Optional[str] = None,
    action: Optional[str] = None,
    target_record_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 200,
    db_path: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Query and filter audit trail records."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = """
        SELECT a.id, a.event_type as action, a.actor_id, u.username as user_name,
               a.target_type, a.target_id as record_id, a.details_json, a.created_at
        FROM audit_log a
        LEFT JOIN users u ON a.actor_id = u.id
    """
    conditions = []
    params: List[Any] = []

    if action:
        conditions.append("a.event_type = ?")
        params.append(action.strip().upper())

    eff_target_id = target_record_id or target_id
    if eff_target_id:
        conditions.append("a.target_id = ?")
        params.append(eff_target_id.strip())

    if target_type:
        conditions.append("a.target_type = ?")
        params.append(target_type.strip())

    if user:
        clean_user = user.strip()
        conditions.append("(u.username LIKE ? OR a.details_json LIKE ?)")
        params.append(f"%{clean_user}%")
        params.append(f"%{clean_user}%")

    if start_date:
        conditions.append("a.created_at >= ?")
        params.append(start_date.strip())

    if end_date:
        conditions.append("a.created_at <= ?")
        params.append(end_date.strip())

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY a.id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        details = {}
        if r["details_json"]:
            try:
                details = json.loads(r["details_json"])
            except Exception:
                pass

        resolved_user = r["user_name"] or details.get("actor_username") or (f"User#{r['actor_id']}" if r["actor_id"] else "System/Guest")

        logs.append({
            "id": r["id"],
            "action": r["action"],
            "event_type": r["action"],
            "actor_id": r["actor_id"],
            "user": resolved_user,
            "target_type": r["target_type"],
            "record_id": r["record_id"],
            "target_id": r["record_id"],
            "details": details,
            "created_at": r["created_at"],
        })
    return logs


# Alias for backward compatibility
get_audit_logs = get_audit_log


def get_audit_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return aggregated metrics for audit dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_events FROM audit_log")
    total_events = cursor.fetchone()["total_events"]

    cursor.execute("SELECT event_type, COUNT(*) as cnt FROM audit_log GROUP BY event_type ORDER BY cnt DESC")
    action_counts = {r["event_type"]: r["cnt"] for r in cursor.fetchall()}

    cursor.execute("SELECT COUNT(DISTINCT actor_id) as unique_actors FROM audit_log WHERE actor_id IS NOT NULL")
    unique_actors = cursor.fetchone()["unique_actors"]

    conn.close()

    return {
        "total_events": total_events,
        "action_breakdown": action_counts,
        "unique_actors": unique_actors,
    }


def register_audit_routes(router: Router, db_path: Optional[str] = None):
    """Register audit log query endpoints guarded by Admin or Auditor role."""
    from zrevixdb.auth import require_role

    @router.get("/api/audit")
    @require_role("Admin", "Auditor", db_path=db_path)
    def list_audit_logs_route(req: Request) -> Response:
        action = req.query.get("action", [None])[0]
        user = req.query.get("user", [None])[0]
        target_id = req.query.get("record_id", req.query.get("target_id", [None]))[0]
        start_date = req.query.get("start_date", [None])[0]
        end_date = req.query.get("end_date", [None])[0]
        limit_param = req.query.get("limit", ["100"])[0]

        try:
            limit = int(limit_param)
        except (ValueError, TypeError):
            limit = 100

        logs = get_audit_log(
            user=user,
            action=action,
            target_record_id=target_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            db_path=db_path,
        )
        summary = get_audit_summary(db_path=db_path)

        return Response.json({
            "logs": logs,
            "count": len(logs),
            "summary": summary,
        })
