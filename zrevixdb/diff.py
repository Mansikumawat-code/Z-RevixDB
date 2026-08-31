"""Field-level JSON data comparison and version diffing engine.

Pure Python 3 standard library: dict/set algorithms, json. No external libraries.
"""

from typing import Any, Dict, List, Optional, Tuple

from zrevixdb.auth import require_auth
from zrevixdb.server import Request, Response, Router
from zrevixdb.versioning import get_version


def compute_field_diff(old_data: Dict[str, Any], new_data: Dict[str, Any], prefix: str = "") -> List[Dict[str, Any]]:
    """Recursively compute field-level additions, removals, changes, and unchanged fields."""
    if not isinstance(old_data, dict):
        old_data = {}
    if not isinstance(new_data, dict):
        new_data = {}

    old_keys = set(old_data.keys())
    new_keys = set(new_data.keys())
    all_keys = sorted(old_keys | new_keys)

    diff_entries = []

    for key in all_keys:
        field_path = f"{prefix}.{key}" if prefix else key

        if key in new_keys and key not in old_keys:
            # Field added
            diff_entries.append({
                "field": field_path,
                "type": "added",
                "old_value": None,
                "new_value": new_data[key],
            })
        elif key in old_keys and key not in new_keys:
            # Field removed
            diff_entries.append({
                "field": field_path,
                "type": "removed",
                "old_value": old_data[key],
                "new_value": None,
            })
        else:
            # Field present in both
            val_old = old_data[key]
            val_new = new_data[key]

            if isinstance(val_old, dict) and isinstance(val_new, dict):
                # Recurse into nested dictionary
                nested_diffs = compute_field_diff(val_old, val_new, prefix=field_path)
                diff_entries.extend(nested_diffs)
            elif val_old != val_new:
                # Field changed
                diff_entries.append({
                    "field": field_path,
                    "type": "changed",
                    "old_value": val_old,
                    "new_value": val_new,
                })
            else:
                # Field unchanged
                diff_entries.append({
                    "field": field_path,
                    "type": "unchanged",
                    "old_value": val_old,
                    "new_value": val_new,
                })

    return diff_entries


def compare_versions(
    record_id: str,
    v1_num: int,
    v2_num: int,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Load two versions of a record and produce a comprehensive structural diff."""
    v1 = get_version(record_id, v1_num, db_path=db_path)
    if not v1:
        raise KeyError(f"Version {v1_num} not found for record '{record_id}'")

    v2 = get_version(record_id, v2_num, db_path=db_path)
    if not v2:
        raise KeyError(f"Version {v2_num} not found for record '{record_id}'")

    fields = compute_field_diff(v1["data"], v2["data"])

    added_count = sum(1 for f in fields if f["type"] == "added")
    removed_count = sum(1 for f in fields if f["type"] == "removed")
    changed_count = sum(1 for f in fields if f["type"] == "changed")
    unchanged_count = sum(1 for f in fields if f["type"] == "unchanged")

    return {
        "record_id": record_id,
        "collection": v1.get("collection", ""),
        "key": v1.get("key", ""),
        "v1": {
            "version_num": v1["version_num"],
            "created_at": v1["created_at"],
            "commit_message": v1["commit_message"],
            "author": v1["author_username"],
            "checksum": v1["checksum"],
            "data": v1["data"],
        },
        "v2": {
            "version_num": v2["version_num"],
            "created_at": v2["created_at"],
            "commit_message": v2["commit_message"],
            "author": v2["author_username"],
            "checksum": v2["checksum"],
            "data": v2["data"],
        },
        "summary": {
            "total_fields": len(fields),
            "added_count": added_count,
            "removed_count": removed_count,
            "changed_count": changed_count,
            "unchanged_count": unchanged_count,
            "has_changes": (added_count + removed_count + changed_count) > 0,
        },
        "diff": fields,
    }


def register_diff_routes(router: Router, db_path: Optional[str] = None):
    """Register version comparison and diff API routes."""

    @router.get("/api/records/:id/compare")
    @require_auth(db_path=db_path)
    def compare_records_route(req: Request) -> Response:
        record_id = req.path_params.get("id")
        from_param = req.query.get("from", req.query.get("from_v", [None]))[0]
        to_param = req.query.get("to", req.query.get("to_v", [None]))[0]

        if not from_param or not to_param:
            return Response.json(
                {"error": "Query parameters 'from' and 'to' version numbers are required (e.g. ?from=1&to=2)"},
                status=400,
            )

        try:
            v1_num = int(from_param)
            v2_num = int(to_param)
        except (ValueError, TypeError):
            return Response.json({"error": "Version numbers must be valid integers"}, status=400)

        try:
            diff_result = compare_versions(record_id, v1_num, v2_num, db_path=db_path)
            return Response.json(diff_result)
        except KeyError as e:
            return Response.json({"error": str(e)}, status=404)
        except Exception as e:
            return Response.json({"error": f"Diff computation failed: {e}"}, status=500)
