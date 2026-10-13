# Digital Footprint Exposure Scanner

A privacy-first digital exposure assessment and cleanup assistant.

## Objective

Help users understand where their verified digital identifiers may have appeared in known exposure datasets and convert those findings into an actionable cleanup plan.

## Core Principles

- Ownership verification before exposure results
- No plaintext password handling
- Client-side password k-anonymity
- Licensed/legitimate intelligence sources only
- Data minimization
- HMAC-based identifier protection
- Encryption in transit and at rest
- User-controlled cleanup
- No guarantee of deletion from criminal sources
- Explicit coverage limitations

## Target stack

```text
React + Vite
      ↓
FastAPI
      ↓
SQLite
      ↓
Background scan worker
      ↓
Provider abstraction
      ├── Mock provider
      └── HIBP adapter
```

The first version runs locally in a Codespace. It does not require Docker,
Redis, PostgreSQL, Terraform, or AWS services.

## Phase 0: project foundation

- Python 3.12 and Node.js 22 development container
- FastAPI health endpoint at `/health`
- React/Vite product shell
- Backend tests and frontend production build

Run the backend from `backend/`:

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Run the backend tests from `backend/`:

```bash
pytest -q
```

Run the frontend from `frontend/`:

```bash
npm install
npm run dev -- --host 0.0.0.0
```

Build the frontend from `frontend/`:

```bash
npm run build
```

## Security

Passwords should never enter the backend.

Identifiers are normalized and protected using HMAC where possible.

Raw intelligence-provider responses are not persisted.

## Phase 3: simulated exposure-scanning foundation

Only verified identifiers owned by the authenticated user can be scanned.
`POST /identifiers/{identifier_id}/scans` creates a new scan for each request;
`GET /scans/{scan_id}` only returns scans belonging to the authenticated user.
The current workflow runs synchronously and persists pending, running, and
completed or failed lifecycle states.

The only provider is a deterministic mock. Its findings are labelled as
simulated and unverified, and must not be represented as real exposure data.
The mock receives no identifier value. Scan submissions are limited per user
to five requests per 15 minutes by default; configure this with
`SCAN_RATE_LIMIT_ATTEMPTS` and `SCAN_RATE_LIMIT_WINDOW_SECONDS`.

The scan rate limiter is in-memory, so its state is local to one application
process and is lost on restart. It is not a security boundary for multi-worker
or multi-instance deployments; use a shared store before deploying that way.
Existing SQLite databases need the new `exposure_scans` table created through
the project's explicit `python -m app.db.init_db` setup command before using
the scan endpoints. This milestone does not run that command or change the live
database.

If the process stops after persisting a scan as `RUNNING`, the record remains
in that state until `recover_stale_scans` is explicitly invoked. Recovery is
not run automatically at application startup, since another worker may still
be running the scan. In production, invoke it from a single scheduled
maintenance job using a cutoff older than the provider's enforced maximum run
time plus a safety margin, and a dedicated database session. Do not enable
scheduled recovery until provider execution has a defined upper bound.

Scan state commits are rolled back and database exceptions propagated when a
commit fails. A failure to persist the final result can leave the previously
committed scan in `RUNNING`; the explicit stale-scan recovery policy handles
that interrupted state. Simulated findings remain mock examples, not evidence
of actual exposure.

## Status

Phase 3 - Simulated exposure-scanning foundation
