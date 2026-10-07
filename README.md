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

## Status

Phase 0 - Project Foundation
