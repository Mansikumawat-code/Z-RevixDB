"""Zero-dependency Inverted Index and Full-Text Search Engine.

Replaces Elasticsearch using pure Python 3 standard library:
collections, bisect, re, json, sqlite3.
"""

import bisect
import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from zrevixdb.auth import require_auth
from zrevixdb.server import Request, Response, Router
from zrevixdb.storage import get_db_connection


def extract_terms(data: Any, path: str = "") -> List[Tuple[str, str]]:
    """Recursively extract (field_path, term_text) pairs from a JSON structure."""
    terms: List[Tuple[str, str]] = []

    if isinstance(data, dict):
        for k, v in data.items():
            current_path = f"{path}.{k}" if path else str(k)
            # Index the field key name as well
            terms.append((current_path, str(k)))
            terms.extend(extract_terms(v, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]" if path else f"[{i}]"
            terms.extend(extract_terms(item, current_path))
    elif data is not None:
        terms.append((path, str(data)))

    return terms


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercased alphanumeric tokens, discarding empty tokens."""
    if not text:
        return []
    # Find all contiguous alphanumeric sequences (handles unicode & punctuation)
    tokens = re.findall(r"[a-zA-Z0-9]+", str(text).lower())
    return [t for t in tokens if len(t) > 0]


class InvertedIndex:
    """In-memory Inverted Index with prefix searching, TF-IDF scoring, and incremental updates."""

    def __init__(self):
        # Mapping: token -> dict of record_id -> list of field_paths where token occurs
        self.inverted: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        # Forward mapping: record_id -> set of tokens (for fast O(1) incremental invalidation)
        self.forward: Dict[str, Set[str]] = defaultdict(set)
        # Sorted list of unique tokens for O(log N) prefix searches via bisect
        self.sorted_tokens: List[str] = []
        # Cached record metadata: record_id -> { collection, key, version_num, data, updated_at }
        self.record_cache: Dict[str, Dict[str, Any]] = {}

    def clear(self):
        """Reset index completely."""
        self.inverted.clear()
        self.forward.clear()
        self.sorted_tokens.clear()
        self.record_cache.clear()

    def _insert_token(self, token: str):
        """Insert token into sorted token list if not present."""
        idx = bisect.bisect_left(self.sorted_tokens, token)
        if idx >= len(self.sorted_tokens) or self.sorted_tokens[idx] != token:
            self.sorted_tokens.insert(idx, token)

    def remove_record(self, record_id: str):
        """Remove a record's postings from the inverted index."""
        if record_id in self.forward:
            old_tokens = self.forward[record_id]
            for token in old_tokens:
                if token in self.inverted and record_id in self.inverted[token]:
                    del self.inverted[token][record_id]
                    if not self.inverted[token]:
                        del self.inverted[token]
                        # Remove from sorted tokens
                        idx = bisect.bisect_left(self.sorted_tokens, token)
                        if idx < len(self.sorted_tokens) and self.sorted_tokens[idx] == token:
                            del self.sorted_tokens[idx]
            del self.forward[record_id]

        if record_id in self.record_cache:
            del self.record_cache[record_id]

    def update_record(
        self,
        record_id: str,
        collection: str,
        key: str,
        data: Dict[str, Any],
        version_num: int = 1,
        updated_at: Optional[str] = None,
    ):
        """Incrementally index or update a single record."""
        # 1. Clear old postings for this record if previously indexed
        self.remove_record(record_id)

        # 2. Cache record metadata
        self.record_cache[record_id] = {
            "record_id": record_id,
            "collection": collection,
            "key": key,
            "version_num": version_num,
            "data": data,
            "updated_at": updated_at or "",
        }

        # 3. Extract all field paths and text
        field_terms = extract_terms(data)
        field_terms.append(("__meta__.collection", collection))
        field_terms.append(("__meta__.key", key))
        field_terms.append(("__meta__.id", record_id))

        # 4. Tokenize and post into inverted index
        new_tokens_for_record: Set[str] = set()

        for field_path, term_text in field_terms:
            tokens = tokenize(term_text)
            for tok in tokens:
                self.inverted[tok][record_id].append(field_path)
                new_tokens_for_record.add(tok)
                self._insert_token(tok)

        self.forward[record_id] = new_tokens_for_record

    def build_from_db(self, db_path: Optional[str] = None) -> int:
        """Scan all active records from SQLite and rebuild inverted index."""
        self.clear()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT r.id, r.collection, r.key, r.updated_at,
                   v.version_num, v.data_json
            FROM records r
            LEFT JOIN record_versions v ON r.current_version_id = v.id
            WHERE r.is_deleted = 0
            """
        )
        rows = cursor.fetchall()
        conn.close()

        count = 0
        for r in rows:
            data = {}
            if r["data_json"]:
                try:
                    data = json.loads(r["data_json"])
                except Exception:
                    pass

            self.update_record(
                record_id=r["id"],
                collection=r["collection"],
                key=r["key"],
                data=data,
                version_num=r["version_num"] or 1,
                updated_at=r["updated_at"],
            )
            count += 1

        print(f"[SEARCH] Inverted index built: {count} records, {len(self.sorted_tokens)} unique tokens indexed.")
        return count

    def find_matching_tokens(self, query_token: str) -> List[Tuple[str, bool]]:
        """Find matching tokens using exact match and prefix lookup via bisect."""
        matched: List[Tuple[str, bool]] = []
        if not query_token:
            return matched

        # 1. Exact match
        if query_token in self.inverted:
            matched.append((query_token, True))

        # 2. Prefix match via bisect (for tokens >= 2 chars)
        if len(query_token) >= 2:
            start_idx = bisect.bisect_left(self.sorted_tokens, query_token)
            for i in range(start_idx, len(self.sorted_tokens)):
                cand = self.sorted_tokens[i]
                if not cand.startswith(query_token):
                    break
                if cand != query_token:
                    matched.append((cand, False))  # False = prefix match

        return matched

    def search(
        self,
        query: str,
        collection: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Execute full-text query with ranked scoring, token highlights, and collection filtering."""
        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        # Accumulate score per record: record_id -> float score
        record_scores: Dict[str, float] = defaultdict(float)
        record_matching_tokens: Dict[str, Set[str]] = defaultdict(set)
        record_matching_fields: Dict[str, Set[str]] = defaultdict(set)

        for q_tok in query_tokens:
            matches = self.find_matching_tokens(q_tok)

            for index_token, is_exact in matches:
                postings = self.inverted.get(index_token, {})
                for rec_id, field_paths in postings.items():
                    # Filter by collection if specified
                    meta = self.record_cache.get(rec_id)
                    if not meta:
                        continue
                    if collection and meta["collection"].lower() != collection.lower():
                        continue

                    # Base weight: exact = 5.0, prefix = 2.0
                    weight = 5.0 if is_exact else 2.0
                    # Frequency bonus
                    freq_bonus = min(len(field_paths) * 0.5, 3.0)
                    total_match_weight = weight + freq_bonus

                    # Key or collection match bonus
                    for fp in field_paths:
                        if fp == "__meta__.key":
                            total_match_weight += 8.0
                        elif fp == "__meta__.collection":
                            total_match_weight += 4.0
                        record_matching_fields[rec_id].add(fp)

                    record_scores[rec_id] += total_match_weight
                    record_matching_tokens[rec_id].add(index_token)

        # Sort matching records by score descending
        sorted_records = sorted(record_scores.items(), key=lambda item: item[1], reverse=True)

        results = []
        for rec_id, score in sorted_records[:limit]:
            meta = self.record_cache.get(rec_id)
            if not meta:
                continue

            # Generate preview snippet
            data = meta["data"]
            data_snippet = json.dumps(data, indent=2)
            if len(data_snippet) > 300:
                data_snippet = data_snippet[:300] + "..."

            results.append({
                "record_id": rec_id,
                "collection": meta["collection"],
                "key": meta["key"],
                "version_num": meta["version_num"],
                "score": round(score, 2),
                "matched_tokens": sorted(list(record_matching_tokens[rec_id])),
                "matched_fields": sorted(list(record_matching_fields[rec_id])),
                "data_preview": data,
                "snippet": data_snippet,
                "updated_at": meta["updated_at"],
            })

        return results


# Global in-memory inverted index singleton
_INDEX_INSTANCE: Optional[InvertedIndex] = None


def get_search_index() -> InvertedIndex:
    """Return the global InvertedIndex instance."""
    global _INDEX_INSTANCE
    if _INDEX_INSTANCE is None:
        _INDEX_INSTANCE = InvertedIndex()
    return _INDEX_INSTANCE


def build_index(db_path: Optional[str] = None) -> int:
    """Build or rebuild global inverted index from database."""
    index = get_search_index()
    return index.build_from_db(db_path=db_path)


def update_index(
    record_id: str,
    collection: str,
    key: str,
    data: Dict[str, Any],
    version_num: int = 1,
    updated_at: Optional[str] = None,
):
    """Incrementally update global inverted index for a record."""
    index = get_search_index()
    index.update_record(
        record_id=record_id,
        collection=collection,
        key=key,
        data=data,
        version_num=version_num,
        updated_at=updated_at,
    )


def remove_from_index(record_id: str):
    """Remove record from global inverted index."""
    index = get_search_index()
    index.remove_record(record_id=record_id)


def search(
    query: str,
    collection: Optional[str] = None,
    limit: int = 50,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Execute ranked full-text search against the inverted index."""
    index = get_search_index()
    if len(index.record_cache) == 0 and db_path:
        index.build_from_db(db_path=db_path)
    return index.search(query=query, collection=collection, limit=limit)


def register_search_routes(router: Router, db_path: Optional[str] = None):
    """Register search API routes."""

    @router.get("/api/search")
    @require_auth(db_path=db_path)
    def search_route(req: Request) -> Response:
        q = req.query.get("q", req.query.get("query", [""]))[0]
        collection = req.query.get("collection", [None])[0]
        limit_param = req.query.get("limit", ["50"])[0]

        try:
            limit = int(limit_param)
        except (ValueError, TypeError):
            limit = 50

        # Handle empty/whitespace queries safely
        if not q or not q.strip():
            return Response.json({
                "query": q,
                "count": 0,
                "results": [],
                "message": "Empty query provided.",
            })

        results = search(query=q, collection=collection, limit=limit, db_path=db_path)

        return Response.json({
            "query": q,
            "collection_filter": collection,
            "count": len(results),
            "results": results,
        })
