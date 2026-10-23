# YewNo Release (YNR): Technical Documentation

**Version 1.0.0 · For engineers**

YNR is a self hosted unified search layer: heterogeneous personal/enterprise data
sources are normalized into a single encrypted SQLite index and exposed through a
minimal authenticated HTTP API with full text search.

---

## 1. Architecture

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Connectors │   │  Connectors │   │  Connectors │     (Gmail, SMS bridge,
│   (push)    │   │   (push)    │   │   (push)    │      IoT hub, bank feed,
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘      social, filesystem…)
       │  POST /api/ingest  (normalized item schema)
       ▼
┌────────────────────────────────────────────────┐
│  FastAPI app (main.py)                           │
│  ├─ Auth middleware   (opaque bearer sessions)   │
│  ├─ Rate limiter      (token bucket / IP+route)  │
│  ├─ Ingest pipeline   (encrypt-if-sensitive)     │
│  ├─ Search            (SQLite FTS5, bm25 rank)   │
│  └─ Audit logger      (append-only)              │
└───────────────┬──────────────────────────────────┘
                ▼
┌────────────────────────────────────────────────┐
│  SQLite  (data/ynr.db)                           │
│  users · items · items_fts (FTS5) · audit_log    │
└────────────────────────────────────────────────┘
```

**Design decisions and their rationale**

| Decision | Why |
|---|---|
| Push based connectors | Connectors own their source's auth and polling cadence; the core never holds third party credentials. Failure isolation: a dead connector degrades one source, not the system. |
| SQLite + FTS5 | Zero ops, single file, ACID. FTS5 with `bm25()` ranking covers sub 100ms search to ~10M rows. Swap point for Postgres+pgvector or OpenSearch is isolated to `init_db()`/`search()`. |
| Opaque sessions over JWT | Instantly revocable, nothing decodable client side, no alg confusion surface. Horizontal scaling later → move `SessionStore` to Redis; interface is 3 methods. |
| Field level encryption, not full disk only | Sensitive sources are ciphertext *inside* the DB, so a leaked `ynr.db` without `.ynr_master.key` exposes only titles of sensitive items. |

## 2. Data model

```sql
users      (id, username UNIQUE, password_hash, created_at)
items      (id, user_id FK, source, title, body, body_enc BLOB, meta JSON, ts)
items_fts  FTS5(title, body) content-synced to items via AFTER INSERT trigger;
           the indexed body is body || ' ' || source so source names are queryable
audit_log  (id, ts, user_id, action, detail, ip)
```

Invariant: for any item, exactly one of `body` / `body_enc` is non null.
Sensitive sources (`banking`, `bills`, `social`) populate `body_enc`;
**their bodies are deliberately excluded from the FTS index**: titles only.
This is a stated security/recall tradeoff: ciphertext can't be indexed without
either decrypt on index (plaintext index = pointless encryption) or more exotic
schemes (SSE/HE). If you need full text over sensitive bodies, the supported
path is an encrypted at rest disk + moving the source out of `SENSITIVE_SOURCES`.

## 3. Security model

**Threat model**: stolen DB file, credential stuffing, token theft from logs,
API scraping, SQL/FTS injection.

- **Passwords**: `PBKDF2-HMAC-SHA256`, 600,000 iterations (OWASP ≥2023), 16 byte
  per user salt, constant time comparison via `hmac.compare_digest`.
- **Sessions**: `secrets.token_urlsafe(32)` → 256 bit opaque tokens, server side
  store, 8h sliding TTL, explicit revocation on logout. Bearer header only; no cookies → no CSRF surface.
- **Encryption at rest**: Fernet (`AES-128-CBC + HMAC-SHA256`, authenticated).
  Master key: file with `0600` perms locally; **in production inject via KMS/Vault**
  (`_load_or_create_master_key()` is the single swap point).
- **Rate limiting**: token bucket, 30 req/10s per `(IP, route)`; separate buckets
  for `register`/`login` throttle credential stuffing.
- **Injection**: all SQL parameterized; FTS queries are rewritten into quoted
  prefix tokens (`"tok"*`) so user input can never reach FTS5 query syntax.
- **Audit**: every register/login (success *and* failure)/ingest/search appended
  with timestamp + IP. Detail strings truncated to 500 chars to prevent log stuffing.
- **Headers**: `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, restrictive CSP via middleware.
- **Isolation**: every query is scoped `WHERE user_id = ?` from the session, never
  from client input. Cross tenant reads are structurally impossible.

## 4. API reference

All request/response bodies are JSON. Auth = `Authorization: Bearer <token>`.

| Method | Route | Auth | Body / params | Returns |
|---|---|---|---|---|
| POST | `/api/register` | none | `{username, password}` (pw ≥ 10 chars) | `{ok}` · 409 taken |
| POST | `/api/login` | none | `{username, password}` | `{token}` · 401 |
| POST | `/api/logout` | ✓ | none | `{ok}` |
| POST | `/api/ingest` | ✓ | `{source, title, body?, meta?, ts?}` | `{ok}` · 400 bad source |
| GET | `/api/search` | ✓ | `?q=&source=all&limit=50` | `{results:[{id,source,title,snippet,meta,ts,sensitive}], query}` |
| GET | `/api/sources` | ✓ | none | `{sources:[{name,count}]}` |
| GET | `/api/docs` | none | none | OpenAPI/Swagger UI |

Errors: standard HTTP codes; 429 on rate limit; `{detail: "..."}` body.

## 5. Writing a connector

A connector is anything that can POST. Contract:

1. Authenticate (login once, reuse token until 401, then log in again).
2. Normalize each record to `{source, title, body, meta, ts}` where `source`
   ∈ `SOURCES` and `ts` is epoch seconds.
3. POST to `/api/ingest`. Idempotency is the connector's job (track your own
   cursor/history id; e.g. Gmail `historyId`, IMAP UID, file mtime).

Twenty line Gmail example:

```python
import requests, time
s = requests.Session()
tok = s.post(f"{BASE}/api/login", json=CREDS).json()["token"]
s.headers["Authorization"] = f"Bearer {tok}"
for msg in fetch_new_gmail_messages(since=cursor):   # your Gmail API code
    s.post(f"{BASE}/api/ingest", json={
        "source": "gmail",
        "title": msg["subject"],
        "body": msg["snippet"],
        "meta": {"from": msg["from"], "id": msg["id"]},
        "ts": msg["epoch"],
    })
```

## 6. Run, test, deploy

```bash
pip install fastapi uvicorn cryptography requests
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000     # serves API + UI at /
python3 seed_demo.py                             # demo user + 20 items + smoke tests
```

Production checklist:
- TLS terminate in front (Caddy/nginx); never run plain HTTP past localhost.
- Move master key to KMS; mount `data/` on encrypted volume; back up `ynr.db` (it's one file).
- Set `uvicorn --workers N` behind the proxy; move `SessionStore`/`RateLimiter` to Redis when N > 1 (both are in process today, the documented single node limitation).
- Point of scale: `items` past ~10M rows or needing vector/semantic search → Postgres + pgvector; the search interface is one function.

## 7. Known limitations (read before filing issues)

- Session + rate limit state is in process: restarts log everyone out; multi worker needs Redis.
- Sensitive bodies are not full text searchable (by design, §2).
- Web connector is a fallthrough stub; wire it to your search API of choice.
- No 2FA yet; the auth module is deliberately small so TOTP drops in cleanly.
