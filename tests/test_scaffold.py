"""Smoke tests for Z-RevixDB scaffold using standard library unittest."""

import os
import sqlite3
import threading
import time
import unittest
import urllib.request
import urllib.error
import json

from zrevixdb.storage import init_db, get_db_connection, DEFAULT_DB_PATH
from zrevixdb.server import Router, run_server, Response


class TestScaffold(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup test db
        cls.test_db_path = os.path.join(os.path.dirname(__file__), "test_db.sqlite3")
        init_db(cls.test_db_path)

        # Setup test server on port 8001
        cls.router = Router()

        @cls.router.get("/api/ping")
        def ping_handler(req):
            return Response.json({"message": "pong"})

        cls.port = 8001
        cls.server = run_server(host="127.0.0.1", port=cls.port, router=cls.router)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def test_database_schema(self):
        """Verify that all required tables exist in SQLite."""
        conn = get_db_connection(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]
        conn.close()

        expected_tables = ["users", "sessions", "records", "record_versions", "audit_log"]
        for table in expected_tables:
            self.assertIn(table, tables, f"Table {table} missing from schema")

    def test_root_serves_html(self):
        """Verify GET / returns index.html placeholder."""
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            content_type = resp.headers.get("Content-Type")
            self.assertIn("text/html", content_type)
            body = resp.read().decode("utf-8")
            self.assertIn("Z-REVIX", body)
            self.assertIn("Git remembers your code", body)

    def test_static_asset_serving(self):
        """Verify GET /static/css/style.css returns CSS."""
        url = f"http://127.0.0.1:{self.port}/static/css/style.css"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            content_type = resp.headers.get("Content-Type")
            self.assertIn("text/css", content_type)
            body = resp.read().decode("utf-8")
            self.assertIn("--bg-primary", body)

    def test_api_route_dispatch(self):
        """Verify custom router route dispatch."""
        url = f"http://127.0.0.1:{self.port}/api/ping"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("message"), "pong")

    def test_404_route(self):
        """Verify 404 response for unknown routes."""
        url = f"http://127.0.0.1:{self.port}/nonexistent"
        try:
            urllib.request.urlopen(url)
            self.fail("Expected HTTPError 404")
        except urllib.error.HTTPError as e:
            try:
                self.assertEqual(e.code, 404)
            finally:
                e.close()


if __name__ == "__main__":
    unittest.main()
