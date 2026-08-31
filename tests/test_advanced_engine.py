"""Comprehensive tests for Time Travel, Version Diffing, and Cryptographic Integrity Verification."""

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

from zrevixdb.auth import create_user, register_auth_routes
from zrevixdb.diff import compare_versions, compute_field_diff, register_diff_routes
from zrevixdb.integrity import (
    compute_version_hmac,
    get_or_create_hmac_secret,
    register_integrity_routes,
    verify_all,
    verify_record,
)
from zrevixdb.server import Router, run_server
from zrevixdb.storage import get_db_connection, init_db
from zrevixdb.versioning import (
    create_record,
    get_current,
    get_state_at,
    register_record_routes,
    update_record,
)


class TestAdvancedEngine(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), "test_advanced_unit.sqlite3")
        init_db(self.test_db)
        self.user = create_user("test_admin", "AdminPass123", role="Admin", db_path=self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_time_travel_get_state_at(self):
        """Test point-in-time time travel accurately resolves state across version history."""
        # V1
        v1_data = {"cluster": "us-east-1", "nodes": 3, "status": "initializing"}
        rec = create_record(
            collection="infrastructure",
            key="k8s_prod",
            data=v1_data,
            user=self.user,
            commit_message="Initial cluster config",
            db_path=self.test_db,
        )
        rec_id = rec["id"]

        # Ensure distinct timestamps
        time.sleep(0.05)
        t_after_v1 = datetime.datetime.now(datetime.timezone.utc).isoformat()
        time.sleep(0.05)

        # V2
        v2_data = {"cluster": "us-east-1", "nodes": 10, "status": "active", "ingress": "traefik"}
        update_record(
            record_id=rec_id,
            new_data=v2_data,
            user=self.user,
            commit_message="Scale to 10 nodes and add ingress",
            db_path=self.test_db,
        )

        time.sleep(0.05)
        t_after_v2 = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Query past timestamp (after V1, before V2) -> must return V1
        state_v1 = get_state_at(rec_id, timestamp_str=t_after_v1, db_path=self.test_db)
        self.assertIsNotNone(state_v1)
        self.assertEqual(state_v1["matched_version_num"], 1)
        self.assertEqual(state_v1["data"], v1_data)

        # Query timestamp after V2 -> must return V2
        state_v2 = get_state_at(rec_id, timestamp_str=t_after_v2, db_path=self.test_db)
        self.assertIsNotNone(state_v2)
        self.assertEqual(state_v2["matched_version_num"], 2)
        self.assertEqual(state_v2["data"], v2_data)

        # Query timestamp before record was created -> must return None
        state_before = get_state_at(rec_id, timestamp_str="2020-01-01T00:00:00Z", db_path=self.test_db)
        self.assertIsNone(state_before)

    def test_version_diffing(self):
        """Test structural field-level diff identifies added, removed, changed, and unchanged keys."""
        data1 = {
            "name": "Widget Alpha",
            "price": 10.00,
            "deprecated_flag": True,
            "metadata": {"env": "staging", "region": "us-west"},
        }
        data2 = {
            "name": "Widget Alpha",  # unchanged
            "price": 14.50,          # changed
            "sku": "WIDG-999",       # added
            # deprecated_flag removed
            "metadata": {"env": "production", "region": "us-west"},  # nested changed / unchanged
        }

        diff_entries = compute_field_diff(data1, data2)
        diff_by_field = {d["field"]: d for d in diff_entries}

        # Check name (unchanged)
        self.assertEqual(diff_by_field["name"]["type"], "unchanged")

        # Check price (changed)
        self.assertEqual(diff_by_field["price"]["type"], "changed")
        self.assertEqual(diff_by_field["price"]["old_value"], 10.00)
        self.assertEqual(diff_by_field["price"]["new_value"], 14.50)

        # Check sku (added)
        self.assertEqual(diff_by_field["sku"]["type"], "added")
        self.assertEqual(diff_by_field["sku"]["new_value"], "WIDG-999")

        # Check deprecated_flag (removed)
        self.assertEqual(diff_by_field["deprecated_flag"]["type"], "removed")
        self.assertEqual(diff_by_field["deprecated_flag"]["old_value"], True)

        # Check nested metadata.env (changed)
        self.assertEqual(diff_by_field["metadata.env"]["type"], "changed")
        self.assertEqual(diff_by_field["metadata.env"]["old_value"], "staging")
        self.assertEqual(diff_by_field["metadata.env"]["new_value"], "production")

        # Test compare_versions function
        rec = create_record(
            collection="catalog",
            key="widget_a",
            data=data1,
            user=self.user,
            db_path=self.test_db,
        )
        update_record(
            record_id=rec["id"],
            new_data=data2,
            user=self.user,
            commit_message="Price bump and prod promote",
            db_path=self.test_db,
        )

        res = compare_versions(rec["id"], v1_num=1, v2_num=2, db_path=self.test_db)
        self.assertTrue(res["summary"]["has_changes"])
        self.assertEqual(res["summary"]["added_count"], 1)
        self.assertEqual(res["summary"]["removed_count"], 1)
        self.assertTrue(res["summary"]["changed_count"] >= 2)

    def test_cryptographic_integrity_and_tamper_detection(self):
        """Test HMAC-SHA256 signature verification and simulated unauthorized tampering."""
        rec = create_record(
            collection="financial",
            key="ledger_001",
            data={"balance": 500000.00, "currency": "USD"},
            user=self.user,
            commit_message="Initial balance",
            db_path=self.test_db,
        )
        rec_id = rec["id"]

        update_record(
            record_id=rec_id,
            new_data={"balance": 450000.00, "currency": "USD"},
            user=self.user,
            commit_message="Transfer payout",
            db_path=self.test_db,
        )

        # 1. Clean verification must be 100% valid
        verify_res = verify_record(rec_id, db_path=self.test_db)
        self.assertTrue(verify_res["is_valid"])
        self.assertEqual(verify_res["total_versions"], 2)
        self.assertEqual(len(verify_res["anomalies"]), 0)

        all_res = verify_all(db_path=self.test_db)
        self.assertTrue(all_res["is_healthy"])
        self.assertEqual(all_res["compromised_records"], 0)

        # 2. Simulate unauthorized database tampering (directly alter data_json in SQLite)
        conn = get_db_connection(self.test_db)
        tampered_json = json.dumps({"balance": 999999999.00, "currency": "USD"}, sort_keys=True)
        conn.execute(
            "UPDATE record_versions SET data_json = ? WHERE record_id = ? AND version_num = 2",
            (tampered_json, rec_id),
        )
        conn.commit()
        conn.close()

        # 3. Verification must immediately flag anomaly and identify tamper
        tampered_verify = verify_record(rec_id, db_path=self.test_db)
        self.assertFalse(tampered_verify["is_valid"])
        self.assertEqual(len(tampered_verify["anomalies"]), 1)
        anomaly = tampered_verify["anomalies"][0]
        self.assertEqual(anomaly["version_num"], 2)
        self.assertIn("mismatch", anomaly["error"])
        self.assertNotEqual(anomaly["stored_checksum"], anomaly["expected_checksum"])

        # verify_all must flag system as unhealthy
        all_tampered = verify_all(db_path=self.test_db)
        self.assertFalse(all_tampered["is_healthy"])
        self.assertEqual(all_tampered["compromised_records"], 1)


class TestAdvancedEngineHTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_advanced_http.sqlite3")
        init_db(cls.test_db)

        cls.admin_user = create_user("admin_sec", "AdminPass123", role="Admin", db_path=cls.test_db)
        cls.viewer_user = create_user("viewer_sec", "ViewerPass123", role="Viewer", db_path=cls.test_db)

        # Router & Server setup
        cls.router = Router()
        register_auth_routes(cls.router, db_path=cls.test_db)
        register_record_routes(cls.router, db_path=cls.test_db)
        register_diff_routes(cls.router, db_path=cls.test_db)
        register_integrity_routes(cls.router, db_path=cls.test_db)

        cls.port = 8004
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

    def test_http_time_travel_diff_and_integrity(self):
        """Test API endpoints for time travel, diff, and integrity checks."""
        admin_cookie, _ = self._login("admin_sec", "AdminPass123")
        viewer_cookie, _ = self._login("viewer_sec", "ViewerPass123")

        # 1. Create record V1
        _, rec = self._req(
            "/api/records",
            method="POST",
            body={"collection": "policy", "key": "retention", "data": {"days": 30, "archive": "s3"}},
            cookie_header=admin_cookie,
        )
        rec_id = rec["id"]

        time.sleep(0.05)
        t_v1 = datetime.datetime.now(datetime.timezone.utc).isoformat()
        time.sleep(0.05)

        # 2. Update record V2
        self._req(
            f"/api/records/{rec_id}",
            method="PUT",
            body={"data": {"days": 90, "archive": "glacier", "immutable_lock": True}},
            cookie_header=admin_cookie,
        )

        # 3. Time travel endpoint test
        status, tt_data = self._req(
            f"/api/records/{rec_id}/at?timestamp={urllib.parse.quote(t_v1)}",
            method="GET",
            cookie_header=viewer_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(tt_data["matched_version_num"], 1)
        self.assertEqual(tt_data["data"]["days"], 30)

        # 4. Compare diff endpoint test
        status, diff_data = self._req(
            f"/api/records/{rec_id}/compare?from=1&to=2",
            method="GET",
            cookie_header=viewer_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(diff_data["v1"]["version_num"], 1)
        self.assertEqual(diff_data["v2"]["version_num"], 2)
        self.assertTrue(diff_data["summary"]["has_changes"])

        # 5. Integrity check endpoint test (Viewer blocked with 403, Admin succeeds with 200)
        status, _ = self._req("/api/integrity/check", method="GET", cookie_header=viewer_cookie)
        self.assertEqual(status, 403)

        status, scan_data = self._req("/api/integrity/check", method="GET", cookie_header=admin_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(scan_data["is_healthy"])
        self.assertTrue(scan_data["scanned_records"] >= 1)


if __name__ == "__main__":
    unittest.main()
