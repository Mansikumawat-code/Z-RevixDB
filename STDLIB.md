# Z-RevixDB: Standard Library Substitution Log

This document is the record of every place Z-RevixDB reached for a
Python-standard-library or native-browser primitive instead of a
third-party package, pulled from the actual code in this repository (not
hypothetical examples). Each row names the file where it's used and a
short paragraph on why that approach was chosen over the common
third-party alternative.

| # | Purpose | Typical 3rd-party choice | Z-RevixDB stdlib/native replacement | Where |
|---|---|---|---|---|
| 1 | HTTP server & routing | Flask / FastAPI / Werkzeug | `http.server.ThreadingHTTPServer` + a small hand-rolled `Router` class (regex path matching, `:param` capture, per-method dispatch tables) | `zrevixdb/server.py` |
| 2 | Cookie & session parsing | Starlette/Werkzeug cookie jars | `http.cookies.SimpleCookie` to set/parse the `HttpOnly` session cookie | `zrevixdb/auth.py`, `zrevixdb/server.py` |
| 3 | Database engine | SQLAlchemy / an ORM | `sqlite3` directly, with parameterized queries and `Row` factories for dict-like access; WAL journal mode for concurrent read/write safety | `zrevixdb/storage.py` |
| 4 | Password hashing | `bcrypt` / `passlib` | `hashlib.pbkdf2_hmac("sha256", ...)` with a per-user random salt from `secrets.token_hex`, and `hmac.compare_digest` for constant-time comparison on login | `zrevixdb/auth.py` |
| 5 | Session tokens | `itsdangerous` / JWT libraries | `secrets.token_hex(32)` opaque tokens stored server-side in a `sessions` table with an explicit UTC expiry column | `zrevixdb/auth.py` |
| 6 | Request/response body validation | `pydantic` | Plain `dict.get()` checks with explicit `ValueError`/`400` responses on each route handler | `zrevixdb/versioning.py`, `zrevixdb/auth.py` |
| 7 | Structured diffing | `deepdiff` / `jsondiff` | A hand-written field-level differ that iterates the union of both dicts' keys and buckets each into added/removed/changed/unchanged using plain `set` operations | `zrevixdb/diff.py` |
| 8 | Full-text search / indexing | Elasticsearch / Whoosh | A from-scratch inverted index: a `dict[str, set[str]]` mapping lowercased tokens to record IDs, built with `re` for tokenization and updated incrementally on every write | `zrevixdb/search.py` |
| 9 | Cryptographic integrity / tamper detection | A signing SDK, or trusting the DB's own checksums | `hashlib` + `hmac.new(..., hashlib.sha256)` to sign a canonical JSON representation of each version at write time, verified later with `hmac.compare_digest` | `zrevixdb/integrity.py` |
| 10 | Audit/event logging | A dedicated audit-log or event-store library | A plain `audit_log` SQLite table written via `sqlite3`, with `datetime.now(timezone.utc).isoformat()` timestamps and JSON-serialized `details` | `zrevixdb/audit.py` |
| 11 | Startup health checks / crash recovery | A framework's lifecycle hooks + a monitoring agent | A `recovery.py` module that runs on every `app.py` boot: opens the SQLite file, verifies/creates the schema, re-runs the integrity scan, and rebuilds the search index, all before the HTTP server starts accepting connections | `zrevixdb/recovery.py`, `app.py` |
| 12 | Unique record/session IDs | `uuid` third-party polyfills or a KSUID library | Standard-library `uuid.uuid4()` (truncated hex) for record IDs, `secrets.token_hex` for session/HMAC-secret material | `zrevixdb/versioning.py`, `zrevixdb/auth.py`, `zrevixdb.py` |
| 13 | Testing framework | `pytest` + `pytest-cov` | `unittest`, run via `python -m unittest discover tests`, with `sqlite3.connect(":memory:")`-backed fixtures so tests never touch the real data file | `tests/*.py` |
| 14 | Frontend framework/build step | React / Vue / a Webpack or Vite build | Vanilla HTML5 + CSS3 (custom properties for the design system) + native `fetch()`, `DOMContentLoaded`, and template-literal string rendering — no `npm install`, no bundler | `static/*.html`, `static/css/style.css`, `static/js/app.js` |

## Why this approach (per item)

**1–2. HTTP server & routing, cookies.** `http.server.ThreadingHTTPServer`
gives real concurrent request handling for free, and a ~150-line router
class is enough to get Express/Flask-style `GET`/`POST`/`:param` routing
without pulling in a framework whose main value (middleware ecosystems,
templating, ASGI) this project doesn't need. `http.cookies.SimpleCookie`
already knows how to correctly quote, parse, and round-trip cookie
attributes like `HttpOnly` and `Path`, so there's nothing a third-party
cookie jar adds here.

**3. Database engine.** An ORM buys convenience at the cost of hiding
exactly the thing this project is about: precise control over how rows
are versioned and never overwritten. Writing raw parameterized SQL against
`sqlite3` keeps every INSERT/UPDATE visible and auditable, and WAL mode
gives the concurrent-reader/single-writer behavior a real versioning
engine needs without standing up a separate database server.

**4–5. Password hashing & sessions.** PBKDF2 via `hashlib` is a
NIST-recommended KDF that ships in every Python install — no compiled
extension, no wheel-availability risk. Storing opaque server-side session
tokens instead of a JWT avoids an entire class of "did I validate the
signature/algorithm correctly" bugs that JWT libraries exist to paper
over; a `sessions` table row can simply be deleted to instantly revoke
access, which a stateless JWT cannot do without an extra denylist anyway.

**6. Validation.** `pydantic` is genuinely nice for large APIs with many
nested schemas, but this project's payloads are simple, flat JSON bodies.
Explicit `if not body.get(...)` checks are easy to read top-to-bottom in
each route handler and don't require learning a second schema DSL.

**7. Diffing.** `deepdiff` handles arbitrary nested structures and edge
cases this project doesn't have — records are single-level JSON dicts by
design, so a ~20-line differ over `set(a) | set(b)` is both correct and
trivially auditable, which matters for a feature whose whole point is
"tell me exactly what changed."

**8. Search.** Elasticsearch is a distributed system in its own right —
running it for a hackathon project's search box would violate the "one
command starts everything" rule outright. An in-memory inverted index
rebuilt from SQLite on boot (and updated incrementally on writes) gives
real substring/token search over the current dataset size at zero
operational cost.

**9. Integrity.** HMAC-SHA256 under a server-only secret is exactly what
"prove this wasn't tampered with by someone who has the data but not the
key" requires, and it's a two-function primitive (`hmac.new`,
`hmac.compare_digest`) — no need for a cryptography SDK's key-management
machinery when there's exactly one secret to manage.

**10. Audit logging.** A dedicated audit/event-store product adds a
second system to keep in sync with the primary database. Writing audit
rows into the same SQLite file guarantees they're covered by the same WAL
durability and the same crash-recovery scan as everything else.

**11. Crash recovery.** Framework lifecycle hooks assume a framework;
this project's "boot sequence" is five sequential Python function calls
(check file → check schema → verify hashes → rebuild index → start
serving), which is clearer as plain code in `recovery.py` than as
hooks scattered across decorators.

**12. IDs.** `uuid` and `secrets` are both standard-library and both
cryptographically appropriate for their respective jobs (globally-unique
identifiers vs. unguessable secrets) — there's no gap a third-party ID
library fills here.

**13. Testing.** `unittest` is the framework that ships with Python. Since
the project already commits to zero third-party dependencies at runtime,
using `pytest` just for tests would mean a `requirements-dev.txt` this
project deliberately doesn't have. `unittest`'s `discover` command gives
the same one-command test run.

**14. Frontend.** A build step (Webpack/Vite/npm) would violate the
"vanilla frontend, no build step" hard rule directly. Modern `fetch()`,
CSS custom properties, and template literals cover everything a React/Vue
app would have provided for a project this size — forms, conditional
rendering via string templates, and API calls — without an `npm install`
step standing between a clean checkout and a running app.

## Role-Based Access Control (RBAC) Design

- **`Admin`** — full operational control: user management (`/api/users`
  create/edit), audit log access, integrity checks, record CRUD, and
  version restores.
- **`Manager`** — record CRUD (create/update/delete/restore), but no user
  management or audit-log access.
- **`Auditor`** — read-only compliance role: full audit-log access and
  read access to records/versions/diffs, but cannot write.
- **`Viewer`** — read-only access to current records and historical
  snapshots; cannot write, restore, or view the audit log.

Auditor was kept as a distinct fourth role rather than folded into Admin
so that a compliance reviewer can be granted audit-trail visibility
without also being granted the ability to modify data — a real
separation-of-duties requirement, and a two-line addition given the
`require_role(*roles)` design already takes an arbitrary role list per
route.
