# Digital Footprint Exposure Scanner & Cleanup Assistant

A privacy-first digital exposure assessment and remediation platform.

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

## MVP

- User authentication
- Email and phone ownership verification
- Identifier vault
- Breach exposure scan
- Provider abstraction
- Exposure dashboard
- Risk scoring
- Keep List
- Cleanup plan
- Request tracker
- Password exposure check
- Security controls
- Automated testing
- AWS deployment

## Architecture

React/Vite
→ API Gateway
→ AWS Lambda
→ DynamoDB

Asynchronous scans:

API Gateway
→ Lambda
→ SQS
→ Scan Worker
→ Intelligence Provider
→ Risk Engine
→ DynamoDB

## Security

Passwords never enter the backend.

Identifiers are normalized and protected using HMAC where possible.

Raw intelligence-provider responses are not persisted.

## Status

Phase 0 - Project Foundation
