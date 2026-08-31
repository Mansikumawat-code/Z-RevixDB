"""Structured record management with immutable version history, time-travel, and restoration.

Pure Python 3 standard library: hashlib, json, datetime, sqlite3, secrets.
"""

import datetime
import json
import secrets
from typing import Any, Dict, List, Optional

from zrevixdb.audit import log_action
from zrevixdb.auth import require_auth, require_role
from zrevixdb.integrity import compute_version_hmac
from zrevixdb.search import remove_from_index, update_index
from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import get_db_connection


def create_record(
    collection: str,
    key: str,
    data: Dict[str, Any],
    user: Dict[str, Any],
    commit_message: str = "Initial version",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new record and its immutable first version (V1)."""
    if not collection or not isinstance(collection, str):
        raise ValueError("Collection name is required and must be a string")
    if not key or not isinstance(key, str):
        raise ValueError("Record key is required and must be a string")
    if not isinstance(data, dict):
        raise ValueError("Record data must be a JSON object (dictionary)")

    collection = collection.strip()
    key = key.strip()
    record_id = f"rec_{secrets.token_hex(8)}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data_json = json.dumps(data, sort_keys=True)
    author_id = user.get("id")

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, is_deleted FROM records WHERE collection = ? AND key = ?", (collection, key))
        existing = cursor.fetchone()
        if existing:
            if existing["is_deleted"] == 0:
                raise ValueError(f"Active record already exists with key '{key}' in collection '{collection}'")
            else:
                record_id = existing["id"]
                cursor.execute(
                    "UPDATE records SET is_deleted = 0, updated_at = ? WHERE id = ?",
                    (now_iso, record_id),
                )
        else:
            cursor.execute(
                """
                INSERT INTO records (id, collection, key, is_deleted, created_at, updated_at)
                VALUES (?, ?, ?, 0, ?, ?)
                """,
                (record_id, collection, key, now_iso, now_iso),
            )

        cursor.execute("SELECT MAX(version_num) as max_v FROM record_versions WHERE record_id = ?", (record_id,))
        max_row = cursor.fetchone()
        version_num = (max_row["max_v"] or 0) + 1

        checksum = compute_version_hmac(
            record_id=record_id,
            version_num=version_num,
            data_json=data_json,
            created_at=now_iso,
        )

        cursor.execute(
            """
            INSERT INTO record_versions (record_id, version_num, data_json, checksum, author_id, commit_message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (record_id, version_num, data_json, checksum, author_id, commit_message, now_iso),
        )
        version_id = cursor.lastrowid

        cursor.execute("UPDATE records SET current_version_id = ?, is_deleted = 0 WHERE id = ?", (version_id, record_id))
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()

    # Incrementally update in-memory inverted search index
    try:
        update_index(
            record_id=record_id,
            collection=collection,
            key=key,
            data=data,
            version_num=version_num,
            updated_at=now_iso,
        )
    except Exception as e:
        print(f"[WARN] Failed to update search index: {e}")

    log_action(
        user=user,
        action="RECORD_CREATE",
        target_type="record",
        target_record_id=record_id,
        details={
            "collection": collection,
            "key": key,
            "version": version_num,
            "commit_message": commit_message,
            "checksum": checksum,
        },
        db_path=db_path,
    )

    return {
        "id": record_id,
        "collection": collection,
        "key": key,
        "version_num": version_num,
        "data": data,
        "checksum": checksum,
        "commit_message": commit_message,
        "is_deleted": False,
        "created_at": now_iso,
        "updated_at": now_iso,
        "author": user.get("username", "Unknown"),
    }


def update_record(
    record_id: str,
    new_data: Dict[str, Any],
    user: Dict[str, Any],
    commit_message: str = "Update record",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert an incremented version row without overwriting historical versions."""
    if not isinstance(new_data, dict):
        raise ValueError("Record data must be a JSON object (dictionary)")

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, collection, key, is_deleted, created_at FROM records WHERE id = ?", (record_id,))
    rec = cursor.fetchone()
    if not rec:
        conn.close()
        raise KeyError(f"Record with ID '{record_id}' not found")
    if rec["is_deleted"] == 1:
        conn.close()
        raise ValueError(f"Record '{record_id}' is soft-deleted. Cannot update directly. Restore first.")

    cursor.execute("SELECT MAX(version_num) as max_v FROM record_versions WHERE record_id = ?", (record_id,))
    max_row = cursor.fetchone()
    new_version_num = (max_row["max_v"] or 0) + 1

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data_json = json.dumps(new_data, sort_keys=True)
    author_id = user.get("id")

    checksum = compute_version_hmac(
        record_id=record_id,
        version_num=new_version_num,
        data_json=data_json,
        created_at=now_iso,
    )

    try:
        cursor.execute(
            """
            INSERT INTO record_versions (record_id, version_num, data_json, checksum, author_id, commit_message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (record_id, new_version_num, data_json, checksum, author_id, commit_message, now_iso),
        )
        version_id = cursor.lastrowid

        cursor.execute(
            "UPDATE records SET current_version_id = ?, updated_at = ? WHERE id = ?",
            (version_id, now_iso, record_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()

    # Incrementally update in-memory inverted search index
    try:
        update_index(
            record_id=record_id,
            collection=rec["collection"],
            key=rec["key"],
            data=new_data,
            version_num=new_version_num,
            updated_at=now_iso,
        )
    except Exception as e:
        print(f"[WARN] Failed to update search index: {e}")

    log_action(
        user=user,
        action="RECORD_UPDATE",
        target_type="record",
        target_record_id=record_id,
        details={
            "version": new_version_num,
            "commit_message": commit_message,
            "checksum": checksum,
        },
        db_path=db_path,
    )

    return {
        "id": record_id,
        "collection": rec["collection"],
        "key": rec["key"],
        "version_num": new_version_num,
        "data": new_data,
        "checksum": checksum,
        "commit_message": commit_message,
        "is_deleted": False,
        "created_at": rec["created_at"],
        "updated_at": now_iso,
        "author": user.get("username", "Unknown"),
    }


def restore_version(
    record_id: str,
    version_number: int,
    user: Dict[str, Any],
    commit_message: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Restore a historical version by appending a new version containing historical content."""
    hist_version = get_version(record_id, version_number, db_path=db_path)
    if not hist_version:
        raise KeyError(f"Version {version_number} not found for record '{record_id}'")

    target_data = hist_version["data"]
    if isinstance(target_data, dict) and target_data.get("_deleted") is True:
        raise ValueError(f"Version {version_number} is a deletion tombstone. Choose an active historical version to restore.")

    msg = commit_message or f"Restored from version V{version_number}"

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, collection, key, created_at FROM records WHERE id = ?", (record_id,))
    rec = cursor.fetchone()
    if not rec:
        conn.close()
        raise KeyError(f"Record with ID '{record_id}' not found")

    cursor.execute("SELECT MAX(version_num) as max_v FROM record_versions WHERE record_id = ?", (record_id,))
    max_row = cursor.fetchone()
    new_version_num = (max_row["max_v"] or 0) + 1

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data_json = json.dumps(target_data, sort_keys=True)
    author_id = user.get("id")

    checksum = compute_version_hmac(
        record_id=record_id,
        version_num=new_version_num,
        data_json=data_json,
        created_at=now_iso,
    )

    try:
        cursor.execute(
            """
            INSERT INTO record_versions (record_id, version_num, data_json, checksum, author_id, commit_message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (record_id, new_version_num, data_json, checksum, author_id, msg, now_iso),
        )
        version_id = cursor.lastrowid

        cursor.execute(
            "UPDATE records SET current_version_id = ?, is_deleted = 0, updated_at = ? WHERE id = ?",
            (version_id, now_iso, record_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()

    # Re-index restored record
    try:
        update_index(
            record_id=record_id,
            collection=rec["collection"],
            key=rec["key"],
            data=target_data,
            version_num=new_version_num,
            updated_at=now_iso,
        )
    except Exception as e:
        print(f"[WARN] Failed to update search index: {e}")

    log_action(
        user=user,
        action="RECORD_RESTORE",
        target_type="record",
        target_record_id=record_id,
        details={
            "restored_from_version": version_number,
            "new_version": new_version_num,
            "commit_message": msg,
            "checksum": checksum,
        },
        db_path=db_path,
    )

    return {
        "id": record_id,
        "collection": rec["collection"],
        "key": rec["key"],
        "version_num": new_version_num,
        "restored_from_version": version_number,
        "data": target_data,
        "checksum": checksum,
        "commit_message": msg,
        "is_deleted": False,
        "created_at": rec["created_at"],
        "updated_at": now_iso,
        "author": user.get("username", "Unknown"),
    }


def get_current(record_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve the latest version and metadata for a record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT r.id, r.collection, r.key, r.is_deleted, r.created_at, r.updated_at,
               v.id as version_id, v.version_num, v.data_json, v.checksum,
               v.commit_message, v.created_at as version_created_at,
               u.id as author_id, u.username as author_username
        FROM records r
        LEFT JOIN record_versions v ON r.current_version_id = v.id
        LEFT JOIN users u ON v.author_id = u.id
        WHERE r.id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    data = {}
    if row["data_json"]:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            pass

    return {
        "id": row["id"],
        "collection": row["collection"],
        "key": row["key"],
        "is_deleted": bool(row["is_deleted"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "version_id": row["version_id"],
        "version_num": row["version_num"] or 0,
        "data": data,
        "checksum": row["checksum"] or "",
        "commit_message": row["commit_message"] or "",
        "version_created_at": row["version_created_at"],
        "author_id": row["author_id"],
        "author_username": row["author_username"] or "Unknown",
    }


def get_version(record_id: str, version_number: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve an exact historical state by record ID and version number."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT v.id as version_id, v.record_id, v.version_num, v.data_json,
               v.checksum, v.commit_message, v.created_at,
               u.id as author_id, u.username as author_username,
               r.collection, r.key, r.is_deleted
        FROM record_versions v
        JOIN records r ON v.record_id = r.id
        LEFT JOIN users u ON v.author_id = u.id
        WHERE v.record_id = ? AND v.version_num = ?
        """,
        (record_id, version_number),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    data = {}
    if row["data_json"]:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            pass

    return {
        "record_id": row["record_id"],
        "collection": row["collection"],
        "key": row["key"],
        "version_num": row["version_num"],
        "data": data,
        "checksum": row["checksum"],
        "commit_message": row["commit_message"],
        "created_at": row["created_at"],
        "author_id": row["author_id"],
        "author_username": row["author_username"] or "Unknown",
    }


def get_state_at(
    record_id: str,
    timestamp_str: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Time-travel query: finds the active version at a given point in time."""
    if not timestamp_str:
        return None

    try:
        clean_ts = timestamp_str.strip().replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_ts)
        target_iso = dt.isoformat()
    except Exception:
        target_iso = timestamp_str.strip()

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT v.id as version_id, v.record_id, v.version_num, v.data_json,
               v.checksum, v.commit_message, v.created_at,
               u.id as author_id, u.username as author_username,
               r.collection, r.key, r.is_deleted
        FROM record_versions v
        JOIN records r ON v.record_id = r.id
        LEFT JOIN users u ON v.author_id = u.id
        WHERE v.record_id = ? AND v.created_at <= ?
        ORDER BY v.created_at DESC, v.version_num DESC
        LIMIT 1
        """,
        (record_id, target_iso),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    data = {}
    if row["data_json"]:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            pass

    is_tombstone = bool(data.get("_deleted", False))

    return {
        "record_id": row["record_id"],
        "collection": row["collection"],
        "key": row["key"],
        "target_timestamp": timestamp_str,
        "matched_version_num": row["version_num"],
        "version_created_at": row["created_at"],
        "data": data,
        "is_deleted_at_time": is_tombstone,
        "checksum": row["checksum"],
        "commit_message": row["commit_message"],
        "author_username": row["author_username"] or "Unknown",
    }


def get_history(record_id: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve full ordered version chain with metadata for a record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT v.id, v.record_id, v.version_num, v.checksum, v.commit_message,
               v.created_at, length(v.data_json) as size_bytes,
               u.id as author_id, u.username as author_username
        FROM record_versions v
        LEFT JOIN users u ON v.author_id = u.id
        WHERE v.record_id = ?
        ORDER BY v.version_num ASC
        """,
        (record_id,),
    )
    rows = cursor.fetchall()
    conn.close()

    history = []
    for r in rows:
        history.append({
            "version_id": r["id"],
            "record_id": r["record_id"],
            "version_num": r["version_num"],
            "checksum": r["checksum"],
            "commit_message": r["commit_message"] or "",
            "created_at": r["created_at"],
            "size_bytes": r["size_bytes"],
            "author_id": r["author_id"],
            "author_username": r["author_username"] or "Unknown",
        })
    return history


def delete_record(
    record_id: str,
    user: Dict[str, Any],
    commit_message: str = "Soft deleted record",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Soft-delete record by adding a tombstone version without destroying history."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, collection, key, is_deleted FROM records WHERE id = ?", (record_id,))
    rec = cursor.fetchone()
    if not rec:
        conn.close()
        raise KeyError(f"Record with ID '{record_id}' not found")
    if rec["is_deleted"] == 1:
        conn.close()
        raise ValueError(f"Record '{record_id}' is already deleted")

    cursor.execute("SELECT MAX(version_num) as max_v FROM record_versions WHERE record_id = ?", (record_id,))
    max_row = cursor.fetchone()
    new_version_num = (max_row["max_v"] or 0) + 1

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tombstone_data = {
        "_deleted": True,
        "_deleted_at": now_iso,
        "_deleted_by": user.get("username", "Unknown"),
    }
    data_json = json.dumps(tombstone_data, sort_keys=True)
    author_id = user.get("id")

    checksum = compute_version_hmac(
        record_id=record_id,
        version_num=new_version_num,
        data_json=data_json,
        created_at=now_iso,
    )

    try:
        cursor.execute(
            """
            INSERT INTO record_versions (record_id, version_num, data_json, checksum, author_id, commit_message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (record_id, new_version_num, data_json, checksum, author_id, commit_message, now_iso),
        )
        version_id = cursor.lastrowid

        cursor.execute(
            "UPDATE records SET is_deleted = 1, current_version_id = ?, updated_at = ? WHERE id = ?",
            (version_id, now_iso, record_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()

    # Remove from active search index
    try:
        remove_from_index(record_id)
    except Exception as e:
        print(f"[WARN] Failed to remove record from search index: {e}")

    log_action(
        user=user,
        action="RECORD_DELETE",
        target_type="record",
        target_record_id=record_id,
        details={"version": new_version_num, "commit_message": commit_message},
        db_path=db_path,
    )

    return {
        "id": record_id,
        "is_deleted": True,
        "version_num": new_version_num,
        "commit_message": commit_message,
        "updated_at": now_iso,
    }


def list_records(
    collection: Optional[str] = None,
    include_deleted: bool = False,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List records with current version summary."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = """
        SELECT r.id, r.collection, r.key, r.is_deleted, r.created_at, r.updated_at,
               v.version_num, v.checksum, v.commit_message,
               u.username as author_username
        FROM records r
        LEFT JOIN record_versions v ON r.current_version_id = v.id
        LEFT JOIN users u ON v.author_id = u.id
    """
    conditions = []
    params = []

    if not include_deleted:
        conditions.append("r.is_deleted = 0")
    if collection:
        conditions.append("r.collection = ?")
        params.append(collection)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY r.updated_at DESC"

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    records = []
    for r in rows:
        records.append({
            "id": r["id"],
            "collection": r["collection"],
            "key": r["key"],
            "is_deleted": bool(r["is_deleted"]),
            "version_num": r["version_num"] or 0,
            "checksum": r["checksum"] or "",
            "commit_message": r["commit_message"] or "",
            "author_username": r["author_username"] or "Unknown",
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    return records


def register_record_routes(router: Router, db_path: Optional[str] = None):
    """Register record versioning, time-travel, restore, and CRUD API routes."""

    @router.post("/api/records")
    @require_role("Admin", "Manager", db_path=db_path)
    def create_record_route(req: Request) -> Response:
        body = req.json()
        if not body or not isinstance(body, dict):
            return Response.json({"error": "Invalid JSON body"}, status=400)

        collection = body.get("collection")
        key = body.get("key")
        data = body.get("data")
        commit_message = body.get("commit_message", "Initial version")

        if not collection or not key:
            return Response.json({"error": "Fields 'collection' and 'key' are required"}, status=400)
        if data is None or not isinstance(data, dict):
            return Response.json({"error": "Field 'data' must be a valid JSON object"}, status=400)

        try:
            record = create_record(
                collection=collection,
                key=key,
                data=data,
                user=req.user,
                commit_message=commit_message,
                db_path=db_path,
            )
            return Response.json(record, status=201)
        except ValueError as e:
            return Response.json({"error": str(e)}, status=400)
        except Exception as e:
            return Response.json({"error": f"Failed to create record: {e}"}, status=500)

    @router.get("/api/records")
    @require_auth(db_path=db_path)
    def list_records_route(req: Request) -> Response:
        collection = req.query.get("collection", [None])[0]
        include_del_param = req.query.get("include_deleted", ["false"])[0].lower()
        include_deleted = include_del_param in ("true", "1", "yes")

        records = list_records(collection=collection, include_deleted=include_deleted, db_path=db_path)
        return Response.json({"records": records, "count": len(records)})

    @router.get("/api/records/:id/at")
    @require_auth(db_path=db_path)
    def time_travel_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        timestamp = req.query.get("timestamp", [None])[0]

        if not timestamp:
            return Response.json({"error": "Query parameter 'timestamp' is required (ISO 8601 string)"}, status=400)

        state = get_state_at(record_id, timestamp_str=timestamp, db_path=db_path)
        if not state:
            return Response.json(
                {"error": f"No active version found for record '{record_id}' at timestamp '{timestamp}'"},
                status=404,
            )
        return Response.json(state)

    @router.post("/api/records/:id/restore")
    @require_role("Admin", "Manager", db_path=db_path)
    def restore_record_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        if not record_id:
            return Response.json({"error": "Record ID required"}, status=400)

        body = req.json() or {}
        v_param = body.get("version_num") or body.get("version")
        commit_msg = body.get("commit_message")

        if v_param is None:
            return Response.json({"error": "Field 'version_num' is required in request body"}, status=400)

        try:
            version_num = int(v_param)
        except (ValueError, TypeError):
            return Response.json({"error": f"Invalid version number '{v_param}'"}, status=400)

        try:
            restored = restore_version(
                record_id=record_id,
                version_number=version_num,
                user=req.user,
                commit_message=commit_msg,
                db_path=db_path,
            )
            return Response.json(restored, status=200)
        except KeyError as e:
            return Response.json({"error": str(e)}, status=404)
        except ValueError as e:
            return Response.json({"error": str(e)}, status=400)
        except Exception as e:
            return Response.json({"error": f"Failed to restore record: {e}"}, status=500)

    @router.get("/api/records/:id")
    @require_auth(db_path=db_path)
    def get_record_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        if not record_id:
            return Response.json({"error": "Record ID required"}, status=400)

        rec = get_current(record_id, db_path=db_path)
        if not rec:
            return Response.json({"error": f"Record '{record_id}' not found"}, status=404)
        return Response.json(rec)

    @router.put("/api/records/:id")
    @require_role("Admin", "Manager", db_path=db_path)
    def update_record_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        if not record_id:
            return Response.json({"error": "Record ID required"}, status=400)

        body = req.json()
        if not body or not isinstance(body, dict):
            return Response.json({"error": "Invalid JSON body"}, status=400)

        data = body.get("data")
        commit_message = body.get("commit_message", "Updated record")

        if data is None or not isinstance(data, dict):
            return Response.json({"error": "Field 'data' must be a valid JSON object"}, status=400)

        try:
            updated = update_record(
                record_id=record_id,
                new_data=data,
                user=req.user,
                commit_message=commit_message,
                db_path=db_path,
            )
            return Response.json(updated, status=200)
        except KeyError as e:
            return Response.json({"error": str(e)}, status=404)
        except ValueError as e:
            return Response.json({"error": str(e)}, status=400)
        except Exception as e:
            return Response.json({"error": f"Failed to update record: {e}"}, status=500)

    @router.get("/api/records/:id/history")
    @require_auth(db_path=db_path)
    def get_history_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        if not record_id:
            return Response.json({"error": "Record ID required"}, status=400)

        history = get_history(record_id, db_path=db_path)
        if not history:
            rec = get_current(record_id, db_path=db_path)
            if not rec:
                return Response.json({"error": f"Record '{record_id}' not found"}, status=404)
        return Response.json({"record_id": record_id, "history": history, "total_versions": len(history)})

    @router.get("/api/records/:id/versions/:version_num")
    @require_auth(db_path=db_path)
    def get_version_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        v_str = req.path_params.get("version_num")
        try:
            version_num = int(v_str)
        except (ValueError, TypeError):
            return Response.json({"error": f"Invalid version number '{v_str}'"}, status=400)

        version_data = get_version(record_id, version_num, db_path=db_path)
        if not version_data:
            return Response.json({"error": f"Version {version_num} for record '{record_id}' not found"}, status=404)
        return Response.json(version_data)

    @router.delete("/api/records/:id")
    @require_role("Admin", "Manager", db_path=db_path)
    def delete_record_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        if not record_id:
            return Response.json({"error": "Record ID required"}, status=400)

        body = req.json() or {}
        commit_message = body.get("commit_message", "Soft deleted record")

        try:
            res = delete_record(record_id=record_id, user=req.user, commit_message=commit_message, db_path=db_path)
            return Response.json(res, status=200)
        except KeyError as e:
            return Response.json({"error": str(e)}, status=404)
        except ValueError as e:
            return Response.json({"error": str(e)}, status=400)
        except Exception as e:
            return Response.json({"error": f"Failed to delete record: {e}"}, status=500)
