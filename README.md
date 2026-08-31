# Z-RevixDB

> **Git remembers your code. Z-RevixDB remembers your data.**

**Track D — Data & Storage** | Hackathon submission

An Enterprise Data Versioning, Time-Travel & Recovery Platform built with
**zero third-party runtime dependencies**: pure Python 3 standard library on
the backend, vanilla HTML5/CSS3/JS on the frontend.

---

## 1. The Problem

Version control solved this for source code decades ago. Application data
never got the same treatment. When a record in a production database is
overwritten, the previous state is usually just gone — no diff, no blame,
no time travel, no cryptographic proof the data wasn't tampered with along
the way. Teams bolt on ad-hoc audit columns, or reach for heavyweight
event-sourcing frameworks and search clusters that need their own ops
team. Z-RevixDB asks: what if versioned, auditable, cryptographically
verifiable data storage was as lightweight as `python app.py`?

## 2. Feature List

- **Authentication & RBAC** — PBKDF2-HMAC-SHA256 password hashing, salted
  per-user, HttpOnly session cookies, and four enforced roles (`Admin`,
  `Manager`, `Auditor`, `Viewer`), checked server-side on every route.
- **Immutable Versioning Engine** — every create/update appends a new
  version row; nothing is ever overwritten. Soft-delete is a tombstone
  version, not a `DROP`.
- **Time Travel** — reconstruct the exact state of any record as of any
  timestamp.
- **Version Comparison (Diff)** — field-level added/removed/changed/
  unchanged report between any two versions of a record, computed with
  plain dict/set operations.
- **Cryptographic Integrity Verification** — every version is signed with
  HMAC-SHA256 at write time using a server-held secret; a scan recomputes
  and compares signatures to detect tampering.
- **Point-in-Time Restore** — roll a record back to any historical version
  by appending a *new* version with that old content (the chain only ever
  grows).
- **Crash Recovery** — every boot runs a pre-flight scan: verifies the
  SQLite file and schema, re-checks integrity hashes, and rebuilds the
  in-memory search index before the server accepts a single request.
- **Structured Audit Trail** — every sensitive action (login, logout,
  record CRUD, restore, integrity run, permission denials) is written to
  an `audit_log` table, filterable by user/action/record/date.
- **Custom Full-Text Search** — a from-scratch inverted index (`dict` of
  token → record IDs) with simple relevance scoring, no Elasticsearch.
- **Enterprise Dashboard** — a persistent-nav, 8-page console (Overview,
  Records, Timeline, Compare, Search, Integrity, Audit, Settings) with
  RBAC-aware UI and live backend-driven stats — no mock data anywhere.
- **Compact Standalone Build** — `zrevixdb.py`, a single self-contained
  file with the auth + storage + versioning core, runnable independently
  of the full app (see [§9](#9-standalone-single-file-build)).

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  BROWSER                                                              │
│  static/*.html + css/style.css + js/app.js  (vanilla JS, no build)    │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ fetch() over HTTP, HttpOnly cookie
┌───────────────────────────────▼──────────────────────────────────────┐
│  HTTP LAYER            zrevixdb/server.py                             │
│  ThreadingHTTPServer + a small Router (regex path matching,           │
│  :param capture, method dispatch) + static-file handler               │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │
┌───────────────────────────────▼──────────────────────────────────────┐
│  APPLICATION LAYER                                                    │
│  ┌───────────┐ ┌─────────────┐ ┌──────────┐ ┌────────┐ ┌───────────┐  │
│  │ auth.py   │ │versioning.py│ │ diff.py  │ │search.py│ │dashboard.py│ │
│  │ RBAC,     │ │ immutable   │ │ field-   │ │inverted │ │ live stats │ │
│  │ sessions  │ │ CRUD, time  │ │ level    │ │ index   │ │ aggregator │ │
│  │           │ │ travel,     │ │ diff     │ │         │ │            │ │
│  │           │ │ restore     │ │          │ │         │ │            │ │
│  └───────────┘ └─────────────┘ └──────────┘ └────────┘ └───────────┘  │
│  ┌────────────┐ ┌───────────┐ ┌──────────────┐                        │
│  │integrity.py│ │ audit.py  │ │ recovery.py  │                        │
│  │ HMAC sign  │ │ structured│ │ boot-time    │                        │
│  │ & verify   │ │ audit log │ │ crash-       │                        │
│  │            │ │           │ │ recovery scan│                        │
│  └────────────┘ └───────────┘ └──────────────┘                        │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ parameterized SQL
┌───────────────────────────────▼──────────────────────────────────────┐
│  STORAGE ENGINE        zrevixdb/storage.py                            │
│  SQLite (WAL mode)                                                    │
│  users · sessions · records · record_versions · audit_log             │
└─────────────────────────────────────────────────────────────────────┘
```

## 4. Setup

Requirements: **Python 3.9+**, nothing else.

```bash
cd zrevixdb
python app.py
```

That's it — one command. On first run the app creates `zrevixdb.sqlite3`,
generates a random Admin password (printed to the console **once**), and
starts serving on `http://127.0.0.1:8000`.

To set a specific admin password instead of a random one, set an
environment variable before the first run:

```bash
ZREVIX_ADMIN_PASSWORD=your-password python app.py
```

## 5. Usage Walkthrough

1. **Login** — open `http://127.0.0.1:8000/login.html`, sign in with the
   admin credentials printed on boot.
2. **Create a record** — go to *Records & Lineage* → *+ New Record*, pick a
   collection/key, enter JSON data. This writes **V1**.
3. **Time travel** — open the record's detail view or the *Timeline* page,
   click any historical version node to reconstruct that exact
   point-in-time state.
4. **Compare** — on *Diff & Compare*, pick a record and two version
   numbers to see a field-level added/removed/changed report.
5. **Integrity check** — on *Integrity Monitor*, click *Run Check* to
   recompute every version's HMAC-SHA256 signature and confirm nothing
   has been tampered with.
6. **Restore** — from the *Timeline* page (or the Records detail view),
   click *Restore this version* on any historical node — this appends a
   brand-new version with that old content; nothing is deleted.
7. **Search** — the *Search* page queries the custom inverted index built
   from every current record's field values.
8. **Audit** — Admins/Auditors can review every sensitive action ever
   taken on the *Audit Trail* page, filterable by user, action, record, or
   date range.

## 6. Testing

```bash
python -m unittest discover tests
```

Covers auth/RBAC, storage CRUD, versioning/time-travel/restore, diffing,
search, integrity verification (including simulated tampering), and
crash-recovery scans. All tests run against a temporary SQLite database —
your real `zrevixdb.sqlite3` is never touched.

**Current status: 31/31 tests passing.**

## 7. Dependency Proof

`requirements.txt` contains nothing but a comment — it is intentionally
empty for the life of this project. To verify no non-standard-library
import exists anywhere in the codebase, run:

```bash
python3 - <<'EOF'
import ast, sys, pathlib
stdlib = sys.stdlib_module_names
bad = []
for p in pathlib.Path('.').rglob('*.py'):
    if '__pycache__' in str(p):
        continue
    tree = ast.parse(p.read_text(), filename=str(p))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                top = n.name.split('.')[0]
                if top not in stdlib and top != 'zrevixdb':
                    bad.append((str(p), top))
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split('.')[0]
            if top not in stdlib and top != 'zrevixdb':
                bad.append((str(p), top))
print("Non-stdlib imports found:", bad)
EOF
```

A grep-based sanity check works too — every `^import` / `^from` line in
every `.py` file resolves to a module in `sys.stdlib_module_names` or to
the project's own `zrevixdb` package:

```bash
grep -rEn '^(import|from) ' --include='*.py' . | sort
```

Both checks currently report **zero** third-party imports across the
project (backend and standalone build alike).

## 8. Security / Threat Model

This is a **hackathon-grade implementation**, not a hardened production
security platform. It demonstrates the right *shape* of controls, not a
security audit. Threats considered and their controls:

| Threat | Control |
|---|---|
| Unauthorized access | Session-cookie authentication + server-side RBAC on every sensitive route (`require_auth` / `require_role`), never enforced only in the UI |
| Invalid or expired sessions | Session tokens carry a UTC expiry timestamp, checked on every request; expired tokens are rejected and treated as logged out |
| Malicious input | JSON body validation on every write path (required fields checked, role/collection/key validated); parameterized SQL everywhere, no string-built queries |
| Unexpected data modification / tampering | Every version is signed at write time with HMAC-SHA256 under a server-only secret; `verify_record` / `verify_all` recompute and flag mismatches |
| Corrupted storage | A crash-recovery scan runs on every boot, before the server accepts requests: validates the SQLite file, recreates any missing tables, re-verifies integrity hashes, and rebuilds the search index |
| Unauthorized recovery/restore attempts | `restore_version` is role-gated to `Admin`/`Manager`; the version chain only grows (a bad restore is itself just a new, auditable version) |
| Repudiation ("I didn't do that") | Every sensitive action — login, logout, record CRUD, restore, integrity run, and every permission denial — is written to an immutable `audit_log` row |

Known gaps that a production system would need to close: no HTTPS/TLS
termination (assumed to sit behind a reverse proxy in real deployment), no
rate limiting on login attempts, no CSRF token (relies on `SameSite`
cookie behavior + JSON content-type), and the HMAC secret key is a local
file rather than a managed secret store.

## 9. Standalone Single-File Build

`zrevixdb.py` is a compact, self-contained build of the core engine —
authentication, RBAC, SQLite storage, and immutable versioning (create /
update / time-travel / restore) — in one file, with its own tiny built-in
UI. It shares no code with the modular `zrevixdb/` package by design.

```bash
python zrevixdb.py
# serves on http://127.0.0.1:8010
```

**Included:** auth + RBAC, SQLite schema, immutable create/update/restore,
time travel, a minimal REST API, a one-page vanilla-JS UI.
**Not included** (use the full `python app.py` for these): field-level
diffing, HMAC integrity scanning, crash-recovery diagnostics, the
structured/filterable audit log, full-text search, and the 8-page
enterprise dashboard.

### Reproducible Build Check

`tools_verify_build.py` walks every tracked source file (`.py .html .css
.js .md .txt`, excluding generated artifacts like `*.sqlite3` and the
HMAC secret file) in sorted order and computes a single SHA-256 over
`"<relative_path>\n<file_bytes>"` for each. Run it from a clean checkout:

```bash
python tools_verify_build.py
```

Verified twice from two independent clean checkouts of this exact
codebase — **both runs produced the identical hash** (README.md itself is
excluded from the hash input, since it documents the hash and can't be
part of its own preimage):

```
Files hashed : 34
SHA-256      : 7619a915f8ed6871f63a9573489d9b955a551c34f8c5c4cec82a931b0529bda8
```

## 10. Project Structure

```
zrevixdb/
  app.py                 # entrypoint: init storage, run recovery scan, start server
  zrevixdb.py             # compact standalone single-file build
  tools_verify_build.py  # reproducible-build SHA-256 checker
  requirements.txt       # intentionally empty
  README.md / STDLIB.md
  zrevixdb/
    server.py            # ThreadingHTTPServer + router + static file handler
    auth.py              # PBKDF2 hashing, sessions, RBAC, user management
    storage.py           # SQLite schema + connection helper
    versioning.py        # immutable CRUD, time travel, restore
    diff.py               # field-level version comparison
    search.py             # inverted-index full-text search
    integrity.py          # HMAC-SHA256 signing & verification
    audit.py              # structured audit log
    recovery.py           # boot-time crash-recovery scan
    dashboard.py           # live overview-page stats aggregation
  static/
    *.html                # 8-page enterprise console + login/index
    css/style.css
    js/app.js
  tests/
    test_*.py             # unittest suite (31 tests)
```
