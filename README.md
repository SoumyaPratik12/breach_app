# Digital Footprint Exposure Scanner

A privacy-first digital exposure assessment and cleanup assistant.

## Objective

Help users understand where their verified digital identifiers may have appeared in known exposure datasets and convert those findings into an actionable cleanup plan.

## Core Principles

- Ownership verification before exposure results
- No plaintext password persistence
- HIBP password checks use range-query k-anonymity
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

Create the backend virtual environment from the repository root if it does not
already exist:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Run the backend from `backend/` (activate the root virtual environment first):

```bash
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

Account passwords are processed by the backend for authentication and are
stored as password hashes. The password-exposure endpoint accepts a candidate
password over the application API and uses it transiently to calculate its
SHA-1 hash. Only the first five hexadecimal hash characters are sent to the
Have I Been Pwned Pwned Passwords range API; neither the plaintext password
nor the full hash is sent to that provider. The application does not
intentionally persist the candidate password. Use HTTPS and ensure reverse
proxies and application logging do not capture request bodies. Python does
not guarantee that immutable password strings are erased from process memory.
An exposure count is advisory and a zero count is not a guarantee that a
password is safe.

`POST /password-exposure/check` requires an authenticated bearer token and
accepts `{"password": "..."}`. The response reports whether the password was
found and its occurrence count. Provider errors return a generic unavailable
response. Checks are rate-limited per user in memory; the limit is local to one
process and resets on restart, so a shared limiter is required for
multi-worker or multi-instance deployments.

Identifiers are normalized and protected using HMAC where possible.

Raw intelligence-provider responses are not persisted.

For production, set `ENVIRONMENT=production`, keep
`EXPOSE_DEV_OTP=false`, and provide distinct JWT, OTP-HMAC, identifier-HMAC,
and Fernet encryption secrets through a deployment secrets manager. Each
HMAC/JWT secret must be at least 32 characters, and the encryption key must be
a valid Fernet key. Only `dev`, `prod`, and `production` are accepted
environment values. Production OTP delivery is not integrated yet, so
identifier OTP requests return `503` until a delivery provider is configured.
Do not rotate the identifier encryption key without migrating existing
encrypted identifiers.

### Production configuration and deployment security

- Set `ENVIRONMENT` explicitly to `production` or `prod` for production deployments. Development configurations may use `dev`.
- Unknown environment values are rejected. Do not rely on implicit defaults for production security.
- Configure strong, unique secrets and a valid Fernet encryption key. Do not rotate existing encryption keys without a planned migration, as doing so may make stored encrypted identifiers inaccessible.
- Development OTP exposure is not supported in production. Configure a real OTP delivery provider before enabling production identifier verification.
- The current in-memory rate limiter is process-local and resets on restart. Use a shared rate-limiting backend for multi-worker or multi-instance deployments.
- Ensure application servers, reverse proxies, and error-monitoring systems do not log passwords, OTPs, authorization headers, or request bodies containing sensitive data.
- Scan results are simulated and must not be represented as verified real-world exposure findings until a real provider is integrated and the response schema supports its results.

## Phase 3: simulated exposure-scanning foundation

Only verified identifiers owned by the authenticated user can be scanned.
`POST /identifiers/{identifier_id}/scans` creates a new scan for each request;
`GET /scans/{scan_id}` only returns scans belonging to the authenticated user.
The current workflow runs synchronously and persists pending, running, and
completed or failed lifecycle states.

The only provider is a deterministic mock. Its findings are labelled as
simulated and unverified, and must not be represented as real exposure data.
The mock receives no identifier value. `ExposureFinding` currently fixes
`simulated` to true and `verified` to false; revise the schema and response
handling before enabling a real provider, and do not treat a provider match as
independently verified exposure. Scan submissions are limited per user to
five requests per 15 minutes by default; configure this with
`SCAN_RATE_LIMIT_ATTEMPTS` and `SCAN_RATE_LIMIT_WINDOW_SECONDS`.

The scan and password-check rate limiters are in-memory, so their state is
local to one application process and is lost on restart. They are not security
boundaries for multi-worker or multi-instance deployments; use a shared store
before deploying that way.
On application startup, `init_db` creates any missing tables, including
`exposure_scans`, without deleting existing data. This is table creation only;
schema changes that require migrations still need a migration process.

At application startup, `recover_stale_scans` marks `RUNNING` scans older than
15 minutes as interrupted, using a dedicated database session. This assumes
scan execution cannot legitimately run longer than that timeout; increase the
cutoff if a future provider has a longer enforced maximum run time. In
multi-worker deployments, coordinate startup recovery so another worker does
not have a scan in progress past the configured cutoff.

Scan state commits are rolled back and database exceptions propagated when a
commit fails. A failure to persist the final result can leave the previously
committed scan in `RUNNING`; the explicit stale-scan recovery policy handles
that interrupted state. Simulated findings remain mock examples, not evidence
of actual exposure.

## Status

Phase 3 - Simulated exposure-scanning foundation
