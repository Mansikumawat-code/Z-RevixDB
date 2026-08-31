"""Comprehensive tests for Z-RevixDB Record Versioning, Immutable Lineage, and Time-Travel."""

import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import cookies

from zrevixdb.audit import get_audit_logs
from zrevixdb.auth import create_session, create_user, register_auth_routes
from zrevixdb.server import Router, run_server
from zrevixdb.storage import init_db
from zrevixdb.versioning import (
    create_record,
    delete_record,
    get_current,
    get_history,
    get_version,
    list_records,
    register_record_routes,
    update_record,
)


class TestVersioningModule(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), "test_versioning_unit.sqlite3")
        init_db(self.test_db)
        self.user = create_user("test_admin", "AdminPass123", role="Admin", db_path=self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_create_record_produces_v1(self):
        """Verify creating a record produces V1 with immutable checksum and metadata."""
        data_v1 = {"sku": "A-100", "price": 49.99, "stock": 100}
        rec = create_record(
            collection="inventory",
            key="item_a100",
            data=data_v1,
            user=self.user,
            commit_message="Initial SKU import",
            db_path=self.test_db,
        )

        self.assertIsNotNone(rec["id"])
        self.assertEqual(rec["version_num"], 1)
        self.assertEqual(rec["collection"], "inventory")
        self.assertEqual(rec["key"], "item_a100")
        self.assertEqual(rec["data"], data_v1)
        self.assertTrue(len(rec["checksum"]) == 64)

        # Check in DB
        curr = get_current(rec["id"], db_path=self.test_db)
        self.assertEqual(curr["version_num"], 1)
        self.assertEqual(curr["data"], data_v1)
        self.assertEqual(curr["checksum"], rec["checksum"])

        # Check audit log
        logs = get_audit_logs(target_type="record", target_id=rec["id"], db_path=self.test_db)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["event_type"], "RECORD_CREATE")

    def test_update_record_preserves_immutable_history(self):
        """Verify updating a record creates V2, V3 without mutating V1 or V2."""
        data_v1 = {"tier": "bronze", "limit": 1000}
        rec = create_record(
            collection="plans",
            key="plan_tier",
            data=data_v1,
            user=self.user,
            commit_message="Create bronze plan",
            db_path=self.test_db,
        )
        rec_id = rec["id"]

        # V2 Update
        data_v2 = {"tier": "silver", "limit": 5000}
        rec_v2 = update_record(
            record_id=rec_id,
            new_data=data_v2,
            user=self.user,
            commit_message="Upgrade to silver plan",
            db_path=self.test_db,
        )
        self.assertEqual(rec_v2["version_num"], 2)
        self.assertEqual(rec_v2["data"], data_v2)

        # V3 Update
        data_v3 = {"tier": "gold", "limit": 20000, "priority_support": True}
        rec_v3 = update_record(
            record_id=rec_id,
            new_data=data_v3,
            user=self.user,
            commit_message="Upgrade to gold plan",
            db_path=self.test_db,
        )
        self.assertEqual(rec_v3["version_num"], 3)
        self.assertEqual(rec_v3["data"], data_v3)

        # Head / Current state check
        current_state = get_current(rec_id, db_path=self.test_db)
        self.assertEqual(current_state["version_num"], 3)
        self.assertEqual(current_state["data"], data_v3)

        # Time-Travel Historical Checks
        hist_v1 = get_version(rec_id, version_number=1, db_path=self.test_db)
        self.assertEqual(hist_v1["version_num"], 1)
        self.assertEqual(hist_v1["data"], data_v1)
        self.assertEqual(hist_v1["commit_message"], "Create bronze plan")

        hist_v2 = get_version(rec_id, version_number=2, db_path=self.test_db)
        self.assertEqual(hist_v2["version_num"], 2)
        self.assertEqual(hist_v2["data"], data_v2)
        self.assertEqual(hist_v2["commit_message"], "Upgrade to silver plan")

        # History Chain
        history = get_history(rec_id, db_path=self.test_db)
        self.assertEqual(len(history), 3)
        self.assertEqual([v["version_num"] for v in history], [1, 2, 3])

    def test_soft_deletion(self):
        """Verify soft deletion creates a tombstone version and preserves history."""
        rec = create_record(
            collection="accounts",
            key="acc_99",
            data={"name": "Acme Corp"},
            user=self.user,
            db_path=self.test_db,
        )
        rec_id = rec["id"]

        del_res = delete_record(rec_id, user=self.user, commit_message="Account cancelled", db_path=self.test_db)
        self.assertTrue(del_res["is_deleted"])
        self.assertEqual(del_res["version_num"], 2)

        curr = get_current(rec_id, db_path=self.test_db)
        self.assertTrue(curr["is_deleted"])

        # History still exists
        history = get_history(rec_id, db_path=self.test_db)
        self.assertEqual(len(history), 2)


class TestVersioningHTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_versioning_http.sqlite3")
        init_db(cls.test_db)

        # Create users
        cls.admin_user = create_user("admin_ops", "AdminPass123", role="Admin", db_path=cls.test_db)
        cls.viewer_user = create_user("viewer_auditor", "ViewerPass123", role="Viewer", db_path=cls.test_db)

        # Router & Server setup
        cls.router = Router()
        register_auth_routes(cls.router, db_path=cls.test_db)
        register_record_routes(cls.router, db_path=cls.test_db)

        cls.port = 8003
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
        with urllib.request.urlopen(req) as resp:
            cookie_header = resp.headers.get("Set-Cookie")
            data = json.loads(resp.read().decode("utf-8"))
            return cookie_header, data

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

    def test_crud_and_rbac_flow(self):
        """Test complete HTTP CRUD flow with role enforcement and history inspection."""
        admin_cookie, _ = self._login("admin_ops", "AdminPass123")
        viewer_cookie, _ = self._login("viewer_auditor", "ViewerPass123")

        # 1. Viewer cannot create a record (403)
        status, data = self._req(
            "/api/records",
            method="POST",
            body={"collection": "servers", "key": "srv_01", "data": {"host": "10.0.0.1"}},
            cookie_header=viewer_cookie,
        )
        self.assertEqual(status, 403)

        # 2. Admin creates record (201, V1)
        status, rec_data = self._req(
            "/api/records",
            method="POST",
            body={
                "collection": "servers",
                "key": "srv_01",
                "data": {"host": "10.0.0.1", "cpus": 4, "ram_gb": 16},
                "commit_message": "Provision prod web server",
            },
            cookie_header=admin_cookie,
        )
        self.assertEqual(status, 201)
        self.assertEqual(rec_data["version_num"], 1)
        rec_id = rec_data["id"]

        # 3. Viewer can list records (200)
        status, list_data = self._req("/api/records", method="GET", cookie_header=viewer_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(list_data["count"] >= 1)

        # 4. Admin updates record (200, V2)
        status, v2_data = self._req(
            f"/api/records/{rec_id}",
            method="PUT",
            body={
                "data": {"host": "10.0.0.1", "cpus": 8, "ram_gb": 32},
                "commit_message": "Upgrade CPU and RAM",
            },
            cookie_header=admin_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2_data["version_num"], 2)

        # 5. Viewer inspects current state (200, V2)
        status, curr_data = self._req(f"/api/records/{rec_id}", method="GET", cookie_header=viewer_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(curr_data["version_num"], 2)
        self.assertEqual(curr_data["data"]["cpus"], 8)

        # 6. Viewer inspects history chain (200, 2 versions)
        status, hist_data = self._req(f"/api/records/{rec_id}/history", method="GET", cookie_header=viewer_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(hist_data["total_versions"], 2)

        # 7. Viewer inspects historical V1 state (200)
        status, v1_snapshot = self._req(
            f"/api/records/{rec_id}/versions/1", method="GET", cookie_header=viewer_cookie
        )
        self.assertEqual(status, 200)
        self.assertEqual(v1_snapshot["version_num"], 1)
        self.assertEqual(v1_snapshot["data"]["cpus"], 4)

        # 8. Unauthenticated request blocked (401)
        status, _ = self._req(f"/api/records/{rec_id}", method="GET", cookie_header=None)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
