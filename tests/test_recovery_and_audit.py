"""Comprehensive tests for Crash Recovery, Version Restoration, and Enterprise Audit Trail."""

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

from zrevixdb.audit import get_audit_log, log_action, register_audit_routes
from zrevixdb.auth import create_user, register_auth_routes
from zrevixdb.diff import register_diff_routes
from zrevixdb.integrity import register_integrity_routes
from zrevixdb.recovery import run_crash_recovery_scan
from zrevixdb.server import Router, run_server
from zrevixdb.storage import get_db_connection, init_db
from zrevixdb.versioning import (
    create_record,
    delete_record,
    get_current,
    get_history,
    get_version,
    register_record_routes,
    restore_version,
    update_record,
)


class TestRecoveryAndAuditUnit(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), "test_audit_unit.sqlite3")
        init_db(self.test_db)
        self.admin = create_user("admin_sec", "AdminPass123", role="Admin", db_path=self.test_db)
        self.manager = create_user("manager_ops", "ManagerPass123", role="Manager", db_path=self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_restore_version_creates_new_version_and_preserves_chain(self):
        """Verify restore_version creates a new version with past payload without deleting rows."""
        # 1. Create V1
        v1_data = {"database": "postgresql", "port": 5432, "max_connections": 100}
        rec = create_record("config", "db_cfg", v1_data, self.admin, "Initial config", db_path=self.test_db)
        rec_id = rec["id"]

        # 2. Update to V2
        v2_data = {"database": "postgresql", "port": 5432, "max_connections": 500, "ssl": True}
        update_record(rec_id, v2_data, self.admin, "Scale connections", db_path=self.test_db)

        # 3. Update to V3 (bad config)
        v3_data = {"database": "postgresql", "port": 9999, "max_connections": 10}
        update_record(rec_id, v3_data, self.admin, "Faulty port change", db_path=self.test_db)

        # Verify current head is V3
        head = get_current(rec_id, db_path=self.test_db)
        self.assertEqual(head["version_num"], 3)

        # 4. Restore V2
        restored = restore_version(
            record_id=rec_id,
            version_number=2,
            user=self.admin,
            commit_message="Emergency rollback to stable V2",
            db_path=self.test_db,
        )

        # 5. Verify restored is V4, with V2 content
        self.assertEqual(restored["version_num"], 4)
        self.assertEqual(restored["data"], v2_data)
        self.assertEqual(restored["restored_from_version"], 2)

        # 6. Verify full history has 4 distinct versions
        history = get_history(rec_id, db_path=self.test_db)
        self.assertEqual(len(history), 4)
        self.assertEqual([v["version_num"] for v in history], [1, 2, 3, 4])

        # Verify V1, V2, V3 still intact
        self.assertEqual(get_version(rec_id, 1, db_path=self.test_db)["data"], v1_data)
        self.assertEqual(get_version(rec_id, 2, db_path=self.test_db)["data"], v2_data)
        self.assertEqual(get_version(rec_id, 3, db_path=self.test_db)["data"], v3_data)

    def test_restore_soft_deleted_record(self):
        """Verify restoring a deleted record resurrects it as active."""
        rec = create_record("users", "user_100", {"name": "Bob"}, self.admin, db_path=self.test_db)
        rec_id = rec["id"]

        # Soft delete
        delete_record(rec_id, self.admin, db_path=self.test_db)
        self.assertTrue(get_current(rec_id, db_path=self.test_db)["is_deleted"])

        # Restore V1
        res = restore_version(rec_id, 1, self.admin, "Undelete user", db_path=self.test_db)
        self.assertFalse(res["is_deleted"])
        self.assertEqual(res["version_num"], 3)
        self.assertFalse(get_current(rec_id, db_path=self.test_db)["is_deleted"])

    def test_crash_recovery_scan(self):
        """Test crash recovery pre-flight scan verifies storage and re-indexes."""
        summary = run_crash_recovery_scan(db_path=self.test_db)
        self.assertEqual(summary["status"], "HEALTHY")
        self.assertTrue(summary["sqlite_ok"])
        self.assertTrue(summary["tables_verified"])
        self.assertTrue(summary["indexes_rebuilt"])

        # Verify crash recovery scan is audited
        logs = get_audit_log(action="CRASH_RECOVERY_SCAN", db_path=self.test_db)
        self.assertTrue(len(logs) >= 1)


class TestRecoveryAndAuditHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_audit_http.sqlite3")
        init_db(cls.test_db)

        cls.admin = create_user("admin_chief", "AdminPass123", role="Admin", db_path=cls.test_db)
        cls.auditor = create_user("auditor_compliance", "AuditorPass123", role="Auditor", db_path=cls.test_db)
        cls.viewer = create_user("viewer_guest", "ViewerPass123", role="Viewer", db_path=cls.test_db)

        # Router & Server setup
        cls.router = Router()
        register_auth_routes(cls.router, db_path=cls.test_db)
        register_record_routes(cls.router, db_path=cls.test_db)
        register_diff_routes(cls.router, db_path=cls.test_db)
        register_integrity_routes(cls.router, db_path=cls.test_db)
        register_audit_routes(cls.router, db_path=cls.test_db)

        cls.port = 8005
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

    def _req(self, path, method="GET", body=None, cookie_header=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        headers = {"Content-Type": "application/json"}
        if cookie_header:
            c = cookies.SimpleCookie()
            c.load(cookie_header)
            cookie_items = [f"{k}={m.value}" for k, m in c.items()]
            headers["Cookie"] = "; ".join(cookie_items)

        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            finally:
                e.close()

    def test_audit_trail_captures_all_events_and_rbac(self):
        """Test full audit log capture for login, failed login, 401, 403, record CRUD, restore, and RBAC."""
        # 1. Login success
        status, admin_cookie, _ = self._login("admin_chief", "AdminPass123")
        self.assertEqual(status, 200)

        # 2. Login failure (bad password)
        status, _, _ = self._login("admin_chief", "WrongPassword")
        self.assertEqual(status, 401)

        # 3. Auditor login
        status, auditor_cookie, _ = self._login("auditor_compliance", "AuditorPass123")
        self.assertEqual(status, 200)

        # 4. Viewer login
        status, viewer_cookie, _ = self._login("viewer_guest", "ViewerPass123")
        self.assertEqual(status, 200)

        # 5. Permission denied (403): Viewer tries to create record
        self._req(
            "/api/records",
            method="POST",
            body={"collection": "sec", "key": "k", "data": {"a": 1}},
            cookie_header=viewer_cookie,
        )

        # 6. Unauthorized access (401): Request with no cookie
        self._req("/api/records", method="GET", cookie_header=None)

        # 7. Admin creates record (V1)
        _, rec = self._req(
            "/api/records",
            method="POST",
            body={"collection": "audit_test", "key": "rec_01", "data": {"tier": "free"}},
            cookie_header=admin_cookie,
        )
        rec_id = rec["id"]

        # 8. Admin updates record (V2)
        self._req(
            f"/api/records/{rec_id}",
            method="PUT",
            body={"data": {"tier": "pro"}},
            cookie_header=admin_cookie,
        )

        # 9. Admin restores V1 (V3)
        status, restore_data = self._req(
            f"/api/records/{rec_id}/restore",
            method="POST",
            body={"version_num": 1, "commit_message": "Rollback to free"},
            cookie_header=admin_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(restore_data["version_num"], 3)
        self.assertEqual(restore_data["data"]["tier"], "free")

        # 10. Query audit logs with Auditor role (must succeed)
        status, audit_resp = self._req("/api/audit", method="GET", cookie_header=auditor_cookie)
        self.assertEqual(status, 200)
        logs = audit_resp["logs"]
        actions = [l["action"] for l in logs]

        # Verify captured actions
        self.assertIn("AUTH_LOGIN_SUCCESS", actions)
        self.assertIn("AUTH_LOGIN_FAILED", actions)
        self.assertIn("AUTH_PERMISSION_DENIED", actions)
        self.assertIn("AUTH_UNAUTHORIZED_ACCESS", actions)
        self.assertIn("RECORD_CREATE", actions)
        self.assertIn("RECORD_UPDATE", actions)
        self.assertIn("RECORD_RESTORE", actions)

        # 11. Test audit query filtering by action
        status, filtered = self._req("/api/audit?action=RECORD_RESTORE", method="GET", cookie_header=auditor_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(all(l["action"] == "RECORD_RESTORE" for l in filtered["logs"]))

        # 12. Viewer blocked from /api/audit (403)
        status, _ = self._req("/api/audit", method="GET", cookie_header=viewer_cookie)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
