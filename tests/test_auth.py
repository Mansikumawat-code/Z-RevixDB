"""Comprehensive tests for Z-RevixDB Authentication, Session Management, and RBAC."""

import datetime
import json
import os
import sqlite3
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import cookies

from zrevixdb.auth import (
    SESSION_COOKIE_NAME,
    authenticate_user,
    create_session,
    create_user,
    delete_session,
    get_user_from_session,
    hash_password,
    register_auth_routes,
    seed_admin_user,
    verify_password,
)
from zrevixdb.server import Router, run_server
from zrevixdb.storage import init_db


class TestAuthModule(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), "test_auth_unit.sqlite3")
        init_db(self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_password_hashing_and_verification(self):
        """Test PBKDF2 hashing produces distinct salts and validates correctly."""
        raw_pw = "SuperSecret123!"
        h1, s1 = hash_password(raw_pw)
        h2, s2 = hash_password(raw_pw)

        self.assertNotEqual(s1, s2, "Each hash should use a unique random salt")
        self.assertNotEqual(h1, h2, "Different salts must produce different hashes")

        self.assertTrue(verify_password(h1, s1, raw_pw))
        self.assertTrue(verify_password(h2, s2, raw_pw))
        self.assertFalse(verify_password(h1, s1, "WrongPassword"))

    def test_create_and_authenticate_user(self):
        """Test user creation, duplicate prevention, and authentication."""
        user = create_user("alice", "Password123", role="Manager", db_path=self.test_db)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "Manager")

        # Duplicate username should fail
        with self.assertRaises(ValueError):
            create_user("alice", "AnotherPassword", db_path=self.test_db)

        # Invalid role should fail
        with self.assertRaises(ValueError):
            create_user("bob", "Password123", role="SuperGod", db_path=self.test_db)

        # Authentication success
        auth_user = authenticate_user("alice", "Password123", db_path=self.test_db)
        self.assertIsNotNone(auth_user)
        self.assertEqual(auth_user["username"], "alice")

        # Authentication failure (bad password)
        self.assertIsNone(authenticate_user("alice", "WrongPassword", db_path=self.test_db))

        # Authentication failure (nonexistent user)
        self.assertIsNone(authenticate_user("nonexistent", "Password123", db_path=self.test_db))

    def test_session_lifecycle_and_expiration(self):
        """Test session creation, lookup, expiration, and deletion."""
        user = create_user("charlie", "Password123", role="Viewer", db_path=self.test_db)

        # Create valid session
        token, expires_at = create_session(user["id"], duration_seconds=3600, db_path=self.test_db)
        self.assertEqual(len(token), 64)

        session_user = get_user_from_session(token, db_path=self.test_db)
        self.assertIsNotNone(session_user)
        self.assertEqual(session_user["username"], "charlie")

        # Expired session test
        expired_token, _ = create_session(user["id"], duration_seconds=-10, db_path=self.test_db)
        expired_user = get_user_from_session(expired_token, db_path=self.test_db)
        self.assertIsNone(expired_user, "Expired session should return None and be pruned")

        # Session deletion (logout)
        delete_session(token, db_path=self.test_db)
        self.assertIsNone(get_user_from_session(token, db_path=self.test_db))

    def test_admin_seeding(self):
        """Test initial admin account creation and idempotence."""
        user, pw, created = seed_admin_user(db_path=self.test_db)
        self.assertTrue(created)
        self.assertEqual(user, "admin")
        self.assertTrue(len(pw) >= 8)

        # Verify authentication with seeded password
        auth_admin = authenticate_user("admin", pw, db_path=self.test_db)
        self.assertIsNotNone(auth_admin)
        self.assertEqual(auth_admin["role"], "Admin")

        # Second seed call should be idempotent
        user2, pw2, created2 = seed_admin_user(db_path=self.test_db)
        self.assertFalse(created2)
        self.assertEqual(user2, "admin")
        self.assertEqual(pw2, "")


class TestAuthHTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_auth_http.sqlite3")
        init_db(cls.test_db)

        # Create users with different roles
        create_user("admin_user", "AdminPass123", role="Admin", db_path=cls.test_db)
        create_user("manager_user", "ManagerPass123", role="Manager", db_path=cls.test_db)
        create_user("viewer_user", "ViewerPass123", role="Viewer", db_path=cls.test_db)

        # Router & Server setup
        cls.router = Router()
        register_auth_routes(cls.router, db_path=cls.test_db)

        cls.port = 8002
        cls.server = run_server(host="127.0.0.1", port=cls.port, router=cls.router)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except OSError:
                pass

    def _login(self, username, password):
        """Helper to login and extract session cookie."""
        url = f"http://127.0.0.1:{self.port}/api/login"
        payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                cookie_header = resp.headers.get("Set-Cookie")
                data = json.loads(resp.read().decode("utf-8"))
                return resp.status, cookie_header, data
        except urllib.error.HTTPError as e:
            try:
                return e.code, None, json.loads(e.read().decode("utf-8"))
            finally:
                e.close()

    def _request_with_cookie(self, path, cookie_header, method="GET"):
        """Helper to make request with a cookie."""
        url = f"http://127.0.0.1:{self.port}{path}"
        headers = {}
        if cookie_header:
            # Extract key=value
            c = cookies.SimpleCookie()
            c.load(cookie_header)
            cookie_items = [f"{k}={m.value}" for k, m in c.items()]
            headers["Cookie"] = "; ".join(cookie_items)

        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8")), e.headers
            finally:
                e.close()

    def test_login_success_and_me_endpoint(self):
        """Test login returns cookie and /api/me identifies user."""
        status, cookie_header, data = self._login("admin_user", "AdminPass123")
        self.assertEqual(status, 200)
        self.assertIsNotNone(cookie_header)
        self.assertIn(SESSION_COOKIE_NAME, cookie_header)
        self.assertIn("HttpOnly", cookie_header)
        self.assertEqual(data["user"]["username"], "admin_user")
        self.assertEqual(data["user"]["role"], "Admin")

        # Test /api/me with session cookie
        me_status, me_data, _ = self._request_with_cookie("/api/me", cookie_header)
        self.assertEqual(me_status, 200)
        self.assertEqual(me_data["user"]["username"], "admin_user")

    def test_login_invalid_credentials(self):
        """Test login fails with invalid credentials."""
        status, cookie_header, data = self._login("admin_user", "WrongPassword")
        self.assertEqual(status, 401)
        self.assertIsNone(cookie_header)
        self.assertIn("error", data)

    def test_unauthenticated_access_blocked(self):
        """Test unauthenticated requests to protected endpoints return 401."""
        status, data, _ = self._request_with_cookie("/api/me", None)
        self.assertEqual(status, 401)

        status, data, _ = self._request_with_cookie("/api/admin-only", None)
        self.assertEqual(status, 401)

    def test_rbac_admin_only_endpoint(self):
        """Test RBAC: Admin succeeds (200), Viewer is rejected (403), Manager is rejected (403)."""
        # Admin login
        _, admin_cookie, _ = self._login("admin_user", "AdminPass123")
        status, data, _ = self._request_with_cookie("/api/admin-only", admin_cookie)
        self.assertEqual(status, 200)
        self.assertIn("Welcome Admin", data["message"])

        # Viewer login
        _, viewer_cookie, _ = self._login("viewer_user", "ViewerPass123")
        status, data, _ = self._request_with_cookie("/api/admin-only", viewer_cookie)
        self.assertEqual(status, 403, "Viewer must be blocked from admin-only with 403")
        self.assertIn("Forbidden", data["error"])

        # Manager login
        _, manager_cookie, _ = self._login("manager_user", "ManagerPass123")
        status, data, _ = self._request_with_cookie("/api/admin-only", manager_cookie)
        self.assertEqual(status, 403, "Manager must be blocked from admin-only with 403")

    def test_rbac_multi_role_endpoint(self):
        """Test /api/users accessible to Admin and Manager, blocked for Viewer."""
        _, admin_cookie, _ = self._login("admin_user", "AdminPass123")
        status, data, _ = self._request_with_cookie("/api/users", admin_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(len(data["users"]) >= 3)

        _, manager_cookie, _ = self._login("manager_user", "ManagerPass123")
        status, data, _ = self._request_with_cookie("/api/users", manager_cookie)
        self.assertEqual(status, 200)

        _, viewer_cookie, _ = self._login("viewer_user", "ViewerPass123")
        status, data, _ = self._request_with_cookie("/api/users", viewer_cookie)
        self.assertEqual(status, 403)

    def test_logout(self):
        """Test logout clears session and subsequent requests fail."""
        _, cookie_header, _ = self._login("viewer_user", "ViewerPass123")

        # Verify active
        status, _, _ = self._request_with_cookie("/api/me", cookie_header)
        self.assertEqual(status, 200)

        # Logout
        status, logout_data, logout_headers = self._request_with_cookie("/api/logout", cookie_header, method="POST")
        self.assertEqual(status, 200)
        self.assertIn("Logged out", logout_data["message"])

        # Subsequent /api/me with old cookie must return 401
        status, _, _ = self._request_with_cookie("/api/me", cookie_header)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
