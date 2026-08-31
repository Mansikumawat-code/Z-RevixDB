#!/usr/bin/env python3
"""
Z-RevixDB — Compact Single-File Build
======================================
A self-contained, zero-third-party-dependency build of the Z-RevixDB core:
authentication + RBAC, SQLite storage, and immutable record versioning
(create / update / time-travel / restore), served over a minimal stdlib
HTTP API. Everything lives in this one file on purpose.

Run:
    python zrevixdb.py

Then either:
    curl -X POST http://127.0.0.1:8010/api/login -d '{"username":"admin","password":"<printed on boot>"}' -H "Content-Type: application/json"
or open http://127.0.0.1:8010/ in a browser for a minimal built-in UI.

WHAT THIS FILE INCLUDES (feature parity with the full app):
    - PBKDF2-HMAC-SHA256 password hashing + salted storage       (auth.py)
    - Session tokens via secrets.token_hex + HttpOnly cookies     (auth.py)
    - Role-based access control: Admin / Manager / Auditor/Viewer (auth.py)
    - SQLite schema: users, sessions, records, record_versions    (storage.py)
    - Immutable versioning: create / update / get_current /       (versioning.py)
      get_version / get_history / get_state_at (time travel) /
      restore_version / soft-delete
    - A minimal REST API + a single-page vanilla-JS UI

WHAT REQUIRES THE FULL MODULAR APP (`python app.py` + `zrevixdb/` package):
    - Field-level version diffing                (zrevixdb/diff.py)
    - HMAC-SHA256 cryptographic integrity scanning (zrevixdb/integrity.py)
    - Crash-recovery boot diagnostics             (zrevixdb/recovery.py)
    - Structured audit log with filtering         (zrevixdb/audit.py)
    - Custom inverted-index full-text search       (zrevixdb/search.py)
    - The full 8-page enterprise dashboard UI      (static/*.html)

Same hard rule as the rest of the project: Python 3 standard library only.
"""

import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zrevixdb_standalone.sqlite3")
HOST = "127.0.0.1"
PORT = 8010
SESSION_LIFETIME_HOURS = 24
VALID_ROLES = ("Admin", "Manager", "Auditor", "Viewer")

# --------------------------------------------------------------------------
# Storage layer (compact equivalent of zrevixdb/storage.py)
# --------------------------------------------------------------------------


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            collection TEXT NOT NULL,
            key TEXT NOT NULL,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            current_version_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(collection, key)
        );

        CREATE TABLE IF NOT EXISTS record_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT NOT NULL REFERENCES records(id),
            version_num INTEGER NOT NULL,
            data_json TEXT NOT NULL,
            checksum TEXT NOT NULL,
            commit_message TEXT,
            author_id INTEGER,
            author_username TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_versions_record ON record_versions(record_id);
        """
    )
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Auth layer (compact equivalent of zrevixdb/auth.py)
# --------------------------------------------------------------------------


def hash_password(password: str, salt: str = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return digest.hex(), salt


def create_user(username: str, password: str, role: str = "Viewer"):
    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters")
    if not password or len(password) < 4:
        raise ValueError("Password must be at least 4 characters")
    role = role.strip().capitalize()
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}")

    pw_hash, salt = hash_password(password)
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, salt, role, now_iso()),
        )
        conn.commit()
        return {"id": cur.lastrowid, "username": username, "role": role}
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' already exists")
    finally:
        conn.close()


def verify_login(username: str, password: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row:
        return None
    computed, _ = hash_password(password, row["salt"])
    if not hmac.compare_digest(computed, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now_iso(), expires),
    )
    conn.commit()
    conn.close()
    return token


def get_user_from_session(token: str):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        """
        SELECT s.expires_at, u.id, u.username, u.role
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def delete_session(token: str):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def seed_admin_if_needed():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    if count == 0:
        password = os.environ.get("ZREVIX_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        create_user("admin", password, "Admin")
        print("=" * 60)
        print(" [!] INITIAL ADMIN ACCOUNT CREATED (standalone build)")
        print(f"     Username : admin")
        print(f"     Password : {password}")
        print(" [!] Store this credential safely — shown once.")
        print("=" * 60)


# --------------------------------------------------------------------------
# Versioning layer (compact equivalent of zrevixdb/versioning.py)
# --------------------------------------------------------------------------


def compute_checksum(record_id: str, version_num: int, data_json: str, created_at: str) -> str:
    canonical = json.dumps(json.loads(data_json), sort_keys=True, separators=(",", ":"))
    message = f"record:{record_id}|version:{version_num}|created_at:{created_at}|data:{canonical}"
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def create_record(collection: str, key: str, data: dict, user: dict, commit_message="Initial version"):
    if not isinstance(data, dict):
        raise ValueError("Record data must be a JSON object")
    record_id = "rec_" + uuid.uuid4().hex[:16]
    ts = now_iso()
    data_json = json.dumps(data, sort_keys=True)
    checksum = compute_checksum(record_id, 1, data_json, ts)

    conn = get_db()
    existing = conn.execute(
        "SELECT id, is_deleted FROM records WHERE collection = ? AND key = ?",
        (collection, key),
    ).fetchone()
    if existing and existing["is_deleted"] == 0:
        conn.close()
        raise ValueError(f"Active record already exists with key '{key}' in collection '{collection}'")
    if existing:
        record_id = existing["id"]
        conn.execute(
            "UPDATE records SET is_deleted = 0, updated_at = ? WHERE id = ?",
            (ts, record_id),
        )
    else:
        conn.execute(
            "INSERT INTO records (id, collection, key, is_deleted, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)",
            (record_id, collection, key, ts, ts),
        )
    max_v = conn.execute(
        "SELECT MAX(version_num) v FROM record_versions WHERE record_id = ?",
        (record_id,),
    ).fetchone()["v"]
    version_num = (max_v or 0) + 1
    checksum = compute_checksum(record_id, version_num, data_json, ts)
    cur = conn.execute(
        """INSERT INTO record_versions
           (record_id, version_num, data_json, checksum, commit_message, author_id, author_username, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (record_id, version_num, data_json, checksum, commit_message, user["id"], user["username"], ts),
    )
    conn.execute("UPDATE records SET current_version_id = ? WHERE id = ?", (cur.lastrowid, record_id))
    conn.commit()
    conn.close()
    return get_current(record_id)


def update_record(record_id: str, data: dict, user: dict, commit_message="Update record"):
    conn = get_db()
    rec = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    if not rec:
        conn.close()
        raise KeyError(f"Record '{record_id}' not found")

    max_v = conn.execute(
        "SELECT MAX(version_num) v FROM record_versions WHERE record_id = ?", (record_id,)
    ).fetchone()["v"]
    new_v = (max_v or 0) + 1
    ts = now_iso()
    data_json = json.dumps(data)
    checksum = compute_checksum(record_id, new_v, data_json, ts)

    cur = conn.execute(
        """INSERT INTO record_versions
           (record_id, version_num, data_json, checksum, commit_message, author_id, author_username, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (record_id, new_v, data_json, checksum, commit_message, user["id"], user["username"], ts),
    )
    conn.execute(
        "UPDATE records SET current_version_id = ?, updated_at = ? WHERE id = ?",
        (cur.lastrowid, ts, record_id),
    )
    conn.commit()
    conn.close()
    return get_current(record_id)


def get_current(record_id: str):
    conn = get_db()
    row = conn.execute(
        """
        SELECT r.id, r.collection, r.key, r.is_deleted, r.created_at, r.updated_at,
               v.version_num, v.data_json, v.checksum, v.commit_message, v.author_username
        FROM records r LEFT JOIN record_versions v ON r.current_version_id = v.id
        WHERE r.id = ?
        """,
        (record_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "collection": row["collection"],
        "key": row["key"],
        "is_deleted": bool(row["is_deleted"]),
        "version_num": row["version_num"],
        "data": json.loads(row["data_json"]) if row["data_json"] else {},
        "checksum": row["checksum"],
        "commit_message": row["commit_message"],
        "author": row["author_username"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_version(record_id: str, version_num: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM record_versions WHERE record_id = ? AND version_num = ?",
        (record_id, version_num),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "record_id": record_id,
        "version_num": row["version_num"],
        "data": json.loads(row["data_json"]),
        "checksum": row["checksum"],
        "commit_message": row["commit_message"],
        "author": row["author_username"],
        "created_at": row["created_at"],
    }


def get_history(record_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM record_versions WHERE record_id = ? ORDER BY version_num ASC", (record_id,)
    ).fetchall()
    conn.close()
    return [
        {
            "version_num": r["version_num"],
            "checksum": r["checksum"],
            "commit_message": r["commit_message"],
            "author": r["author_username"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_state_at(record_id: str, timestamp_iso: str):
    """Time travel: find the version that was current at the given instant."""
    conn = get_db()
    row = conn.execute(
        """
        SELECT * FROM record_versions
        WHERE record_id = ? AND created_at <= ?
        ORDER BY version_num DESC LIMIT 1
        """,
        (record_id, timestamp_iso),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "record_id": record_id,
        "version_num": row["version_num"],
        "data": json.loads(row["data_json"]),
        "as_of": timestamp_iso,
        "actual_version_created_at": row["created_at"],
    }


def restore_version(record_id: str, version_num: int, user: dict):
    old = get_version(record_id, version_num)
    if not old:
        raise KeyError(f"Version {version_num} of record '{record_id}' not found")
    return update_record(record_id, old["data"], user, commit_message=f"Restored from version V{version_num}")


def delete_record(record_id: str, user: dict):
    current = get_current(record_id)
    if not current:
        raise KeyError(f"Record '{record_id}' not found")
    if current["is_deleted"]:
        raise ValueError(f"Record '{record_id}' is already deleted")
    tombstone = {
        "_deleted": True,
        "_deleted_at": now_iso(),
        "_deleted_by": user.get("username", "Unknown"),
    }
    result = update_record(record_id, tombstone, user, commit_message="Soft deleted record")
    conn = get_db()
    conn.execute("UPDATE records SET is_deleted = 1, updated_at = ? WHERE id = ?", (now_iso(), record_id))
    conn.commit()
    conn.close()
    result["is_deleted"] = True
    return result


def list_records(include_deleted=False):
    conn = get_db()
    query = """
        SELECT r.id, r.collection, r.key, r.is_deleted, r.updated_at, v.version_num
        FROM records r LEFT JOIN record_versions v ON r.current_version_id = v.id
    """
    if not include_deleted:
        query += " WHERE r.is_deleted = 0"
    query += " ORDER BY r.updated_at DESC"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "collection": r["collection"],
            "key": r["key"],
            "is_deleted": bool(r["is_deleted"]),
            "version_num": r["version_num"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]


# --------------------------------------------------------------------------
# Minimal HTTP layer (compact equivalent of zrevixdb/server.py)
# --------------------------------------------------------------------------

ROUTES = []  # list of (method, regex, handler, roles_or_None)


def route(method, path_pattern, roles=None):
    regex = re.compile("^" + re.sub(r":(\w+)", r"(?P<\1>[^/]+)", path_pattern) + "$")

    def decorator(fn):
        ROUTES.append((method, regex, fn, roles))
        return fn

    return decorator


def get_session_token(handler: BaseHTTPRequestHandler):
    cookie_header = handler.headers.get("Cookie")
    if not cookie_header:
        return None
    c = http.cookies.SimpleCookie()
    c.load(cookie_header)
    morsel = c.get("zrevix_session")
    return morsel.value if morsel else None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.address_string()} - {fmt % args}")

    def _send_json(self, payload, status=200, set_cookie=None, clear_cookie=False):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            cookie = http.cookies.SimpleCookie()
            cookie["zrevix_session"] = set_cookie
            cookie["zrevix_session"]["httponly"] = True
            cookie["zrevix_session"]["path"] = "/"
            self.send_header("Set-Cookie", cookie.output(header="").strip())
        if clear_cookie:
            self.send_header("Set-Cookie", "zrevix_session=; Path=/; Max-Age=0; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            return self._serve_ui()

        for m, regex, fn, roles in ROUTES:
            if m != method:
                continue
            match = regex.match(path)
            if not match:
                continue

            user = get_user_from_session(get_session_token(self))
            if roles is not None:
                if user is None:
                    return self._send_json({"error": "Unauthorized. Please log in."}, 401)
                if user["role"] not in roles:
                    return self._send_json(
                        {"error": f"Forbidden. Requires role: {', '.join(roles)}"}, 403
                    )

            try:
                query = parse_qs(parsed.query)
                return fn(self, user, match.groupdict(), query)
            except KeyError as e:
                return self._send_json({"error": str(e)}, 404)
            except ValueError as e:
                return self._send_json({"error": str(e)}, 400)
            except Exception as e:  # pragma: no cover - defensive
                return self._send_json({"error": f"Internal error: {e}"}, 500)

        self._send_json({"error": "Not found"}, 404)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _serve_ui(self):
        body = MINIMAL_UI_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --------------------------------------------------------------------------
# Route handlers
# --------------------------------------------------------------------------


@route("POST", "/api/login")
def login_route(h: Handler, user, params, query):
    body = h._read_json_body()
    username = body.get("username", "")
    password = body.get("password", "")
    matched = verify_login(username, password)
    if not matched:
        return h._send_json({"error": "Invalid username or password"}, 401)
    token = create_session(matched["id"])
    h._send_json({"message": "Login successful", "user": matched}, 200, set_cookie=token)


@route("POST", "/api/logout")
def logout_route(h: Handler, user, params, query):
    token = get_session_token(h)
    if token:
        delete_session(token)
    h._send_json({"message": "Logged out"}, 200, clear_cookie=True)


@route("GET", "/api/me", roles=VALID_ROLES)
def me_route(h: Handler, user, params, query):
    h._send_json({"user": user})


@route("GET", "/api/records", roles=VALID_ROLES)
def list_records_route(h: Handler, user, params, query):
    include_deleted = query.get("include_deleted", ["false"])[0].lower() == "true"
    h._send_json({"records": list_records(include_deleted)})


@route("POST", "/api/records", roles=("Admin", "Manager"))
def create_record_route(h: Handler, user, params, query):
    body = h._read_json_body()
    if not body.get("collection") or not body.get("key"):
        return h._send_json({"error": "'collection' and 'key' are required"}, 400)
    rec = create_record(
        body["collection"], body["key"], body.get("data", {}), user,
        commit_message=body.get("commit_message", "Initial version"),
    )
    h._send_json(rec, 201)


@route("GET", "/api/records/:id", roles=VALID_ROLES)
def get_record_route(h: Handler, user, params, query):
    rec = get_current(params["id"])
    if not rec:
        return h._send_json({"error": "Record not found"}, 404)
    h._send_json(rec)


@route("PUT", "/api/records/:id", roles=("Admin", "Manager"))
def update_record_route(h: Handler, user, params, query):
    body = h._read_json_body()
    rec = update_record(
        params["id"], body.get("data", {}), user,
        commit_message=body.get("commit_message", "Update record"),
    )
    h._send_json(rec)


@route("DELETE", "/api/records/:id", roles=("Admin", "Manager"))
def delete_record_route(h: Handler, user, params, query):
    rec = delete_record(params["id"], user)
    h._send_json(rec)


@route("GET", "/api/records/:id/history", roles=VALID_ROLES)
def history_route(h: Handler, user, params, query):
    h._send_json({"record_id": params["id"], "history": get_history(params["id"])})


@route("GET", "/api/records/:id/versions/:v", roles=VALID_ROLES)
def get_version_route(h: Handler, user, params, query):
    v = get_version(params["id"], int(params["v"]))
    if not v:
        return h._send_json({"error": "Version not found"}, 404)
    h._send_json(v)


@route("GET", "/api/records/:id/at", roles=VALID_ROLES)
def time_travel_route(h: Handler, user, params, query):
    ts = query.get("timestamp", [None])[0]
    if not ts:
        return h._send_json({"error": "Query parameter 'timestamp' is required"}, 400)
    state = get_state_at(params["id"], ts)
    if not state:
        return h._send_json({"error": "No version found at that timestamp"}, 404)
    h._send_json(state)


@route("POST", "/api/records/:id/restore", roles=("Admin", "Manager"))
def restore_route(h: Handler, user, params, query):
    body = h._read_json_body()
    v = body.get("version_num")
    if v is None:
        return h._send_json({"error": "'version_num' is required"}, 400)
    rec = restore_version(params["id"], int(v), user)
    h._send_json(rec)


@route("POST", "/api/users", roles=("Admin",))
def create_user_route(h: Handler, user, params, query):
    body = h._read_json_body()
    new_user = create_user_fn_wrapper(body)
    h._send_json({"user": new_user}, 201)


def create_user_fn_wrapper(body):
    return create_user(body.get("username", ""), body.get("password", ""), body.get("role", "Viewer"))


# --------------------------------------------------------------------------
# Minimal built-in single-page UI (vanilla JS, no build step)
# --------------------------------------------------------------------------

MINIMAL_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Z-RevixDB Standalone</title>
<style>
  body { font-family: -apple-system, sans-serif; background:#0b0f14; color:#e2e8f0; margin:0; padding:2rem; }
  h1 { color:#22d3ee; }
  input, select { background:#1a2230; color:#e2e8f0; border:1px solid #2d3748; padding:0.5rem; margin:0.25rem 0; width:100%; box-sizing:border-box; }
  button { background:#22d3ee; color:#0b0f14; border:none; padding:0.5rem 1rem; cursor:pointer; font-weight:bold; margin-top:0.5rem; }
  .card { background:#131a24; border:1px solid #2d3748; border-radius:8px; padding:1rem; max-width:640px; margin-bottom:1rem; }
  pre { background:#0b0f14; padding:1rem; overflow:auto; border-radius:6px; }
  .hidden { display: none !important; }
  table { width:100%; border-collapse:collapse; }
  td, th { padding:0.4rem; border-bottom:1px solid #2d3748; text-align:left; font-size:0.85rem; }
</style>
</head>
<body>
  <h1>⚡ Z-RevixDB &mdash; Standalone Build</h1>
  <p>Single-file core: auth + storage + immutable versioning. Full enterprise UI lives in <code>python app.py</code>.</p>

  <div class="card" id="login-card">
    <h3>Login</h3>
    <input id="u" placeholder="username" value="admin">
    <input id="p" placeholder="password" type="password">
    <button onclick="login()">Login</button>
    <div id="login-msg"></div>
  </div>

  <div class="card hidden" id="records-card">
    <h3>Records</h3>
    <button onclick="loadRecords()">Refresh</button>
    <table id="records-table"><thead><tr><th>Collection</th><th>Key</th><th>V</th></tr></thead><tbody></tbody></table>
    <h4>Create Record</h4>
    <input id="coll" placeholder="collection">
    <input id="key" placeholder="key">
    <input id="data" placeholder='{"field":"value"}' value='{"field":"value"}'>
    <button onclick="createRecord()">Create</button>
    <pre id="output"></pre>
  </div>

<script>
async function login() {
  const res = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username: document.getElementById('u').value, password: document.getElementById('p').value})});
  const data = await res.json();
  document.getElementById('login-msg').textContent = res.ok ? ('Logged in as ' + data.user.username + ' (' + data.user.role + ')') : data.error;
  if (res.ok) { document.getElementById('records-card').classList.remove('hidden'); loadRecords(); }
}
async function loadRecords() {
  const res = await fetch('/api/records');
  const data = await res.json();
  const tbody = document.querySelector('#records-table tbody');
  tbody.innerHTML = (data.records || []).map(r => `<tr><td>${r.collection}</td><td>${r.key}</td><td>V${r.version_num}</td></tr>`).join('');
}
async function createRecord() {
  const body = { collection: document.getElementById('coll').value, key: document.getElementById('key').value, data: JSON.parse(document.getElementById('data').value || '{}') };
  const res = await fetch('/api/records', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  document.getElementById('output').textContent = JSON.stringify(await res.json(), null, 2);
  loadRecords();
}
</script>
</body>
</html>"""


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------


def main():
    print("=" * 60)
    print("  Z-REVIXDB — Standalone Single-File Build")
    print("  [stdlib-only | auth + storage + versioning core]")
    print("=" * 60)
    init_db()
    seed_admin_if_needed()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"\n[*] Serving on http://{HOST}:{PORT}  (Ctrl+C to stop)\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
