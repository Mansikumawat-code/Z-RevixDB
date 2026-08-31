"""Comprehensive tests for Zero-Dependency Full-Text Search and Inverted Index Engine."""

import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import cookies

from zrevixdb.auth import create_user, register_auth_routes
from zrevixdb.diff import register_diff_routes
from zrevixdb.integrity import register_integrity_routes
import zrevixdb.search as _search_module
from zrevixdb.search import (
    InvertedIndex,
    build_index,
    extract_terms,
    get_search_index,
    register_search_routes,
    search,
    tokenize,
)
from zrevixdb.server import Router, run_server
from zrevixdb.storage import init_db
from zrevixdb.versioning import (
    create_record,
    delete_record,
    register_record_routes,
    restore_version,
    update_record,
)


class TestSearchUnit(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), "test_search_unit.sqlite3")
        init_db(self.test_db)
        self.user = create_user("search_admin", "AdminPass123", role="Admin", db_path=self.test_db)
        # Reset the global singleton before each test for clean isolation
        _search_module._INDEX_INSTANCE = None
        self.index = InvertedIndex()

    def tearDown(self):
        _search_module._INDEX_INSTANCE = None
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_tokenize_and_term_extraction(self):
        """Verify tokenizer handles punctuation, special characters, casing, and nested JSON."""
        # Special characters & punctuation
        tokens = tokenize("PostgreSQL 16.2 Enterprise -- SSL=True; (High-Availability!)")
        expected = ["postgresql", "16", "2", "enterprise", "ssl", "true", "high", "availability"]
        self.assertEqual(tokens, expected)

        # Empty / whitespace
        self.assertEqual(tokenize(""), [])
        self.assertEqual(tokenize("   \n\t  "), [])
        self.assertEqual(tokenize("!@#$%^&*()_+{}[]:;\"'<>?,./"), [])

        # Nested structure extraction
        nested_data = {
            "service": "billing",
            "limits": [100, 200],
            "metadata": {"tier": "gold_vip", "active": True},
        }
        terms = extract_terms(nested_data)
        term_strings = [t[1] for t in terms]
        self.assertIn("billing", term_strings)
        self.assertIn("100", term_strings)
        self.assertIn("gold_vip", term_strings)

    def test_inverted_index_and_prefix_matching(self):
        """Verify inverted index exact and prefix lookup via bisect."""
        idx = InvertedIndex()
        idx.update_record("rec_1", "infra", "k8s_cluster", {"engine": "kubernetes", "nodes": 12})
        idx.update_record("rec_2", "databases", "db_primary", {"engine": "postgresql", "version": "16.1"})

        # Exact match
        res_exact = idx.search("kubernetes")
        self.assertEqual(len(res_exact), 1)
        self.assertEqual(res_exact[0]["record_id"], "rec_1")

        # Prefix match: "postg" -> matches "postgresql"
        res_prefix = idx.search("postg")
        self.assertEqual(len(res_prefix), 1)
        self.assertEqual(res_prefix[0]["record_id"], "rec_2")

        # Multi-term query: "kubernetes infra"
        res_multi = idx.search("kubernetes infra")
        self.assertEqual(len(res_multi), 1)
        self.assertEqual(res_multi[0]["record_id"], "rec_1")

        # Empty & special character queries should return empty without crashing
        self.assertEqual(idx.search(""), [])
        self.assertEqual(idx.search("!@#$%^&*()"), [])

    def test_incremental_indexing_and_deletion(self):
        """Verify incremental index updates without full re-indexing and deletion removal."""
        # Use a neutral key to ensure search hits are driven by data values, not the key itself
        rec = create_record(
            collection="payment_gateways",
            key="gateway_001",  # neutral key — doesn't contain 'stripe' or 'braintree'
            data={"provider": "stripe", "currency": "eur", "fee_pct": 2.9},
            user=self.user,
            db_path=self.test_db,
        )
        rec_id = rec["id"]

        # Search for "stripe" — must match
        res = search("stripe", db_path=self.test_db)
        self.assertTrue(any(r["record_id"] == rec_id for r in res))

        # 2. Update record data (replace provider with "braintree")
        update_record(
            record_id=rec_id,
            new_data={"provider": "braintree", "currency": "usd", "fee_pct": 2.5},
            user=self.user,
            db_path=self.test_db,
        )

        # "braintree" must be found, "stripe" should no longer match (removed from index)
        res_braintree = search("braintree", db_path=self.test_db)
        self.assertTrue(any(r["record_id"] == rec_id for r in res_braintree))

        res_stripe = search("stripe", db_path=self.test_db)
        self.assertFalse(any(r["record_id"] == rec_id for r in res_stripe),
                         "After update, 'stripe' should no longer match this record")

        # 3. Soft delete record
        delete_record(rec_id, user=self.user, db_path=self.test_db)

        # Must not appear in search at all
        res_del = search("braintree", db_path=self.test_db)
        self.assertFalse(any(r["record_id"] == rec_id for r in res_del),
                         "Deleted record should not appear in search results")

        # 4. Restore record V1 (with "stripe")
        restore_version(rec_id, 1, user=self.user, db_path=self.test_db)

        # "stripe" must match again after restore
        res_restored = search("stripe", db_path=self.test_db)
        self.assertTrue(any(r["record_id"] == rec_id for r in res_restored),
                        "After restore to V1, 'stripe' should match again")



class TestSearchHTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_search_http.sqlite3")
        init_db(cls.test_db)

        cls.user = create_user("search_user", "SearchPass123", role="Viewer", db_path=cls.test_db)
        cls.admin = create_user("search_admin", "AdminPass123", role="Admin", db_path=cls.test_db)

        # Seed records
        create_record(
            "servers", "web_prod_01", {"hostname": "nginx-01.corp", "datacenter": "us-east-1", "ssl": True},
            cls.admin, db_path=cls.test_db,
        )
        create_record(
            "servers", "web_prod_02", {"hostname": "caddy-02.corp", "datacenter": "eu-west-1", "ssl": True},
            cls.admin, db_path=cls.test_db,
        )
        create_record(
            "databases", "db_redis_cache", {"engine": "redis", "memory_mb": 4096, "cluster": "cache-tier"},
            cls.admin, db_path=cls.test_db,
        )

        # Reset and rebuild search index from the integration test DB
        _search_module._INDEX_INSTANCE = None
        build_index(db_path=cls.test_db)

        # Router & Server setup
        cls.router = Router()
        register_auth_routes(cls.router, db_path=cls.test_db)
        register_record_routes(cls.router, db_path=cls.test_db)
        register_search_routes(cls.router, db_path=cls.test_db)

        cls.port = 8006
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

    def test_search_endpoint_queries_and_filters(self):
        """Test HTTP GET /api/search with exact, prefix, collection filter, and special chars."""
        user_cookie, _ = self._login("search_user", "SearchPass123")

        # 1. Search exact term "nginx"
        status, data = self._req("/api/search?q=nginx", cookie_header=user_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["key"], "web_prod_01")

        # 2. Search prefix "red" (matches redis)
        status, data = self._req("/api/search?q=red", cookie_header=user_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(data["count"] >= 1)
        keys = [r["key"] for r in data["results"]]
        self.assertIn("db_redis_cache", keys)

        # 3. Search with collection filter
        status, data = self._req("/api/search?q=ssl&collection=servers", cookie_header=user_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["count"], 2)

        # 4. Search with special characters (safe handling)
        status, data = self._req("/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E%20!%40%23%24%25", cookie_header=user_cookie)
        self.assertEqual(status, 200)

        # 5. Empty search query
        status, data = self._req("/api/search?q=", cookie_header=user_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["count"], 0)

        # 6. Unauthenticated search (401)
        status, _ = self._req("/api/search?q=nginx", cookie_header=None)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
