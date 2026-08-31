"""Authentication, session management, and Role-Based Access Control (RBAC).

Strictly standard library: hashlib, secrets, hmac, datetime, sqlite3.
"""

import datetime
import functools
import hashlib
import hmac
import os
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import get_db_connection

SESSION_COOKIE_NAME = "zrevix_session"
VALID_ROLES = ("Admin", "Manager", "Auditor", "Viewer")


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generate PBKDF2-HMAC-SHA256 password hash and salt."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=100_000,
    )
    return key.hex(), salt


def verify_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    """Verify password against stored PBKDF2 hash using constant-time comparison."""
    computed_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(stored_hash, computed_hash)


def create_user(
    username: str,
    password: str,
    role: str = "Viewer",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new user with hashed password and role."""
    norm_role = role.strip().capitalize()
    if norm_role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")

    if not username or len(username.strip()) < 2:
        raise ValueError("Username must be at least 2 characters")
    if not password or len(password) < 4:
        raise ValueError("Password must be at least 4 characters")

    username = username.strip()
    pw_hash, salt = hash_password(password)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, pw_hash, salt, norm_role, now_iso),
        )
        user_id = cursor.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise ValueError(f"Failed to create user: {e}") from e

    conn.close()
    return {
        "id": user_id,
        "username": username,
        "role": norm_role,
        "created_at": now_iso,
    }


def authenticate_user(
    username: str,
    password: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Verify user credentials and return user dict if valid, or None."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, salt, role, created_at FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    if verify_password(row["password_hash"], row["salt"], password):
        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"],
        }
    return None


def create_session(
    user_id: int,
    duration_seconds: int = 86400,
    db_path: Optional[str] = None,
) -> Tuple[str, str]:
    """Create a new session token and persist to database."""
    token = secrets.token_hex(32)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = (now + datetime.timedelta(seconds=duration_seconds)).isoformat()
    created_at = now.isoformat()

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token, user_id, expires_at, created_at),
    )
    conn.commit()
    conn.close()
    return token, expires_at


def get_user_from_session(
    token: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve and validate active user from session token. Cleans expired sessions."""
    if not token:
        return None

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT s.token, s.expires_at, u.id, u.username, u.role, u.created_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    # Check expiration
    expires_dt = datetime.datetime.fromisoformat(row["expires_at"])
    now_dt = datetime.datetime.now(datetime.timezone.utc)

    if now_dt > expires_dt:
        # Session expired, delete it
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return None

    user = {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
    }
    conn.close()
    return user


def delete_session(token: str, db_path: Optional[str] = None) -> bool:
    """Delete an active session."""
    if not token:
        return False
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def seed_admin_user(db_path: Optional[str] = None) -> Tuple[str, str, bool]:
    """Seed initial Admin user if no Admin exists. Returns (username, password, was_created)."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE role = 'Admin' LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if row:
        return row["username"], "", False

    admin_username = "admin"
    admin_password = os.environ.get("ZREVIX_ADMIN_PASSWORD")
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)

    create_user(
        username=admin_username,
        password=admin_password,
        role="Admin",
        db_path=db_path,
    )
    return admin_username, admin_password, True


def get_current_user(req: Request, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Helper to extract and validate user from request cookie."""
    token = req.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    effective_db = db_path or getattr(req, "db_path", None)
    return get_user_from_session(token, db_path=effective_db)


def require_auth(fn: Optional[Callable[[Request], Response]] = None, *, db_path: Optional[str] = None):
    """Decorator ensuring request is authenticated."""
    def decorator(handler: Callable[[Request], Response]) -> Callable[[Request], Response]:
        @functools.wraps(handler)
        def wrapper(req: Request) -> Response:
            effective_db = db_path or getattr(req, "db_path", None)
            user = get_current_user(req, db_path=effective_db)
            if not user:
                # Log unauthorized access attempt
                from zrevixdb.audit import log_action
                log_action(
                    user=None,
                    action="AUTH_UNAUTHORIZED_ACCESS",
                    target_type="route",
                    target_record_id=req.path,
                    details={"method": req.method, "error": "Missing or invalid session cookie"},
                    db_path=effective_db,
                )
                return Response.json({"error": "Unauthorized. Please log in."}, status=401)
            req.user = user
            return handler(req)
        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


def require_role(*roles: str, db_path: Optional[str] = None) -> Callable[[Callable[[Request], Response]], Callable[[Request], Response]]:
    """Decorator enforcing Role-Based Access Control (RBAC)."""
    normalized_roles = [r.strip().capitalize() for r in roles]

    def decorator(fn: Callable[[Request], Response]) -> Callable[[Request], Response]:
        @functools.wraps(fn)
        def wrapper(req: Request) -> Response:
            effective_db = db_path or getattr(req, "db_path", None)
            user = get_current_user(req, db_path=effective_db)
            if not user:
                from zrevixdb.audit import log_action
                log_action(
                    user=None,
                    action="AUTH_UNAUTHORIZED_ACCESS",
                    target_type="route",
                    target_record_id=req.path,
                    details={"method": req.method, "required_roles": normalized_roles},
                    db_path=effective_db,
                )
                return Response.json({"error": "Unauthorized. Please log in."}, status=401)
            req.user = user

            user_role = user.get("role", "").capitalize()
            if user_role not in normalized_roles:
                from zrevixdb.audit import log_action
                log_action(
                    user=user,
                    action="AUTH_PERMISSION_DENIED",
                    target_type="route",
                    target_record_id=req.path,
                    details={
                        "method": req.method,
                        "user_role": user.get("role"),
                        "required_roles": normalized_roles,
                    },
                    db_path=effective_db,
                )
                return Response.json(
                    {
                        "error": f"Forbidden: Role '{user['role']}' lacks required permission (Requires: {', '.join(normalized_roles)})"
                    },
                    status=403,
                )
            return fn(req)
        return wrapper
    return decorator


def register_auth_routes(router: Router, db_path: Optional[str] = None):
    """Register authentication and RBAC API routes on the router."""

    @router.post("/api/login")
    def login_handler(req: Request) -> Response:
        from zrevixdb.audit import log_action
        body = req.json()
        if not body or not isinstance(body, dict):
            return Response.json({"error": "Invalid JSON body"}, status=400)

        username = body.get("username", "").strip()
        password = body.get("password", "")

        if not username or not password:
            return Response.json({"error": "Username and password are required"}, status=400)

        user = authenticate_user(username, password, db_path=db_path)
        if not user:
            log_action(
                user=username,
                action="AUTH_LOGIN_FAILED",
                target_type="auth",
                target_record_id=username,
                details={"reason": "Invalid credentials", "attempted_username": username},
                db_path=db_path,
            )
            return Response.json({"error": "Invalid username or password"}, status=401)

        token, expires_at = create_session(user["id"], duration_seconds=86400, db_path=db_path)

        log_action(
            user=user,
            action="AUTH_LOGIN_SUCCESS",
            target_type="auth",
            target_record_id=str(user["id"]),
            details={"role": user["role"], "expires_at": expires_at},
            db_path=db_path,
        )

        resp = Response.json({
            "message": "Login successful",
            "user": user,
            "expires_at": expires_at,
        })
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=86400,
            path="/",
            httponly=True,
            samesite="Lax",
        )
        return resp

    @router.post("/api/logout")
    def logout_handler(req: Request) -> Response:
        from zrevixdb.audit import log_action
        token = req.cookies.get(SESSION_COOKIE_NAME)
        user = get_current_user(req, db_path=db_path)
        if token:
            delete_session(token, db_path=db_path)

        if user:
            log_action(
                user=user,
                action="AUTH_LOGOUT",
                target_type="auth",
                target_record_id=str(user["id"]),
                details={"username": user["username"]},
                db_path=db_path,
            )

        resp = Response.json({"message": "Logged out successfully"})
        resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
        return resp

    @router.get("/api/me")
    def me_handler(req: Request) -> Response:
        user = get_current_user(req, db_path=db_path)
        if not user:
            return Response.json({"error": "Unauthorized"}, status=401)
        return Response.json({"user": user})

    @router.get("/api/admin-only")
    @require_role("Admin", db_path=db_path)
    def admin_only_handler(req: Request) -> Response:
        return Response.json({
            "message": "Welcome Admin! You have access to administrative operations.",
            "user": req.user,
        })

    @router.get("/api/users")
    @require_role("Admin", "Manager", "Auditor", db_path=db_path)
    def list_users_handler(req: Request) -> Response:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        users = [
            {"id": r["id"], "username": r["username"], "role": r["role"], "created_at": r["created_at"]}
            for r in rows
        ]
        return Response.json({"users": users})

    @router.post("/api/users")
    @require_role("Admin", db_path=db_path)
    def create_user_handler(req: Request) -> Response:
        from zrevixdb.audit import log_action

        body = req.json()
        if not body or not isinstance(body, dict):
            return Response.json({"error": "Invalid JSON body"}, status=400)

        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        role = body.get("role") or "Viewer"

        try:
            new_user = create_user(username=username, password=password, role=role, db_path=db_path)
        except ValueError as exc:
            return Response.json({"error": str(exc)}, status=400)

        log_action(
            user=req.user,
            action="USER_CREATE",
            target_type="user",
            target_record_id=str(new_user["id"]),
            details={"username": new_user["username"], "role": new_user["role"]},
            db_path=db_path,
        )
        return Response.json({"user": new_user}, status=201)

    @router.put("/api/users/:id")
    @require_role("Admin", db_path=db_path)
    def update_user_handler(req: Request) -> Response:
        from zrevixdb.audit import log_action

        user_id = req.path_params.get("id")
        body = req.json() or {}
        new_role = body.get("role")
        new_password = body.get("password")

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return Response.json({"error": "User not found"}, status=404)

        updates = []
        params: List[Any] = []

        if new_role:
            norm_role = new_role.strip().capitalize()
            if norm_role not in VALID_ROLES:
                conn.close()
                return Response.json({"error": f"Invalid role: {new_role}"}, status=400)
            updates.append("role = ?")
            params.append(norm_role)

        if new_password:
            if len(new_password) < 4:
                conn.close()
                return Response.json({"error": "Password must be at least 4 characters"}, status=400)
            pw_hash, salt = hash_password(new_password)
            updates.append("password_hash = ?")
            updates.append("salt = ?")
            params.extend([pw_hash, salt])

        if not updates:
            conn.close()
            return Response.json({"error": "No changes supplied (role or password required)"}, status=400)

        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()

        cursor.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,))
        updated_row = cursor.fetchone()
        conn.close()

        updated_user = {
            "id": updated_row["id"],
            "username": updated_row["username"],
            "role": updated_row["role"],
            "created_at": updated_row["created_at"],
        }

        log_action(
            user=req.user,
            action="USER_UPDATE",
            target_type="user",
            target_record_id=str(user_id),
            details={"changed_fields": [u.split(" ")[0] for u in updates], "new_role": new_role or None},
            db_path=db_path,
        )
        return Response.json({"user": updated_user})
