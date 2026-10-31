# SSL Tracker

A small, lean, production-grade SSL/TLS certificate tracking and monitoring web application built with Python 3.11+, FastAPI, Jinja2 server-rendered templates, and SQLAlchemy with SQLite.

SSL Tracker connects to user-specified domains over TLS with Server Name Indication (SNI), reads certificates, detects expiration and verification anomalies without crashing, retains a history of all checks, and provides an uncluttered dashboard and command-line interface.

---

## Features

- **Domain Management**:
  - Add individual domains with hostname, custom port (default 443), optional label, and internal notes.
  - Bulk import via multiline paste with real-time reporting of added items, duplicates skipped, and invalid formats rejected.
  - Strict input sanitization (rejects schemes like `https://`, URL paths, query parameters, invalid ports, and non-RFC characters).
  - Uniqueness enforced across `hostname` + `port` combinations.
  - Full edit and cascade delete capabilities.

- **SSL/TLS Certificate Checking**:
  - Connects using SNI with a configurable timeout (default 10s).
  - Collects notAfter expiry date, days remaining, issuer, subject CN, Subject Alternative Names (SANs), SHA-256 fingerprint, and negotiated TLS version.
  - Non-crashing validation fallback: reads full certificate metadata even when the chain is untrusted, expired, self-signed, or has hostname mismatches.
  - Concurrent thread pool execution for checking multiple domains rapidly without blocking the server.
  - Full historical audit log: every check is preserved in `CheckHistory`.

- **Dashboard & Reporting**:
  - Main table sorted by days remaining (soonest expiring first).
  - Intuitive status badges and row color accents:
    - **Green**: > 30 days remaining (OK)
    - **Yellow**: 14 to 30 days remaining (EXPIRING SOON)
    - **Orange**: 7 to 14 days remaining (EXPIRING SOON)
    - **Red**: < 7 days remaining or EXPIRED
    - **Grey**: UNREACHABLE or NOT CHECKED
    - **Purple**: INVALID (untrusted chain or hostname mismatch)
  - Real-time search by hostname or label, and status filtering.
  - Detailed domain inspection view with certificate attributes, SAN list, notes, and full check history.
  - CSV export of all tracked domains and their latest certificate telemetry.
  - Dedicated CLI tool: `python -m app.check --all`.

---

## Status Definitions

| Status | Condition | Description |
|---|---|---|
| **OK** | > 30 days left, chain trusted, hostname matches | Certificate is healthy, fully trusted, and well ahead of expiration. |
| **EXPIRING SOON** | 0 to 30 days left, chain trusted, hostname matches | Certificate requires renewal action within 30 days. |
| **EXPIRED** | Days remaining < 0 | Certificate has passed its `notAfter` timestamp. |
| **INVALID** | Untrusted chain, self-signed, private CA, or hostname mismatch | TLS handshake could not verify trust or domain identity. |
| **UNREACHABLE** | DNS failure, socket timeout, connection refused | Host is offline, firewalled, or port is closed. |
| **NOT CHECKED** | Default state before initial check | Domain added but check has not yet executed. |

---

## Setup & Running

### Requirements
- Python 3.11+ (or 3.10+)
- `pip`

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Environment variables:
- `DATABASE_URL`: SQLAlchemy connection string (default: `sqlite:///./ssl.db`)
- `CHECK_TIMEOUT`: Socket and TLS handshake timeout in seconds (default: `10.0`)
- `HOST`: Server bind address (default: `127.0.0.1`)
- `PORT`: Server bind port (default: `8000`)
- `MAX_WORKERS`: Thread pool concurrency limit for bulk/all checks (default: `10`)

### 3. Run the Web App
Run with Uvicorn (defaulting to 127.0.0.1:8000 locally):
```bash
uvicorn app.main:app --reload
```
To run on a custom host and port:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Or via npm in the development container:
```bash
npm run dev
```

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

---

## Command Line Interface (CLI)

SSL Tracker includes a standalone CLI:

### Check All Tracked Domains
Runs concurrent checks across all tracked domains in the database and prints a table sorted by days remaining:
```bash
python -m app.check --all
```

Print current database values without re-checking:
```bash
python -m app.check --all --no-refresh
```

### Inspect a Single Domain On-The-Fly
Check any external domain directly without saving to the database:
```bash
python -m app.check --domain google.com:443
python -m app.check --domain expired.badssl.com:443
```

---

## Running Tests

Run the full pytest suite (includes unit, integration, and live TLS server tests):
```bash
python -m pytest -v
```

Tests cover:
- Hostname, IP, port, scheme, path, and bulk string parsing & validation.
- Status classification hierarchy and days-remaining calculation.
- Color code mappings and threshold boundaries.
- Live TLS testing against dynamically generated in-process servers:
  - Self-signed certificate server
  - Expired certificate server
  - Unreachable/closed port
- Full FastAPI web client routes (CRUD, bulk import, CSV export).

---

## Decisions & Design Rationale

1. **Two-Stage Handshake Strategy for SSL Checking**:
   Python's built-in `ssl` module terminates connections with `SSLCertVerificationError` when encountering self-signed, private CA, or expired certificates. To meet the requirement of reading certificate details even on failure without crashing, `app/checker.py` first attempts a strict verified handshake (`CERT_REQUIRED`, `check_hostname=True`). If verification fails with an `SSLError`, it reconnects with `check_hostname=False` and `CERT_NONE` to extract the DER bytes, parses them using `cryptography.x509`, computes days remaining, checks SANs/CN matching, and flags the certificate as `INVALID` or `EXPIRED` with the exact diagnostic reason.

2. **Dual-Layer Database Architecture**:
   To ensure fast table rendering and sorting without expensive joins, the `Domain` model caches the latest check results (`status`, `days_remaining`, `not_after`, `issuer`, `tls_version`, etc.). Simultaneously, every check appends an immutable entry to `CheckHistory` linked via foreign key with cascade deletion.

3. **Concurrency with Isolated Sessions**:
   `ThreadPoolExecutor` is used for "Check All" and bulk imports. To prevent SQLite concurrency locking or thread-unsafe SQLAlchemy session sharing, each worker thread opens its own `SessionLocal()` session.

4. **Strict Sanitization**:
   Schemes like `https://` and paths like `/login` are strictly rejected with user-friendly error messages rather than silently coerced, preventing misconfiguration where a user assumes paths or HTTP methods are tracked.

---

## Possible Next Steps (Future Extensions)

*Features intentionally omitted per specification to keep the core codebase lean:*
- **Automated Background Scheduling**: Integration with APScheduler or Celery to run daily certificate health checks automatically.
- **Alert Notifications**: Webhook triggers (Slack, Microsoft Teams, PagerDuty) or SMTP email alerts for certificates entering the `EXPIRING SOON` window.
- **User Authentication & RBAC**: Multi-tenant team accounts with admin/read-only permission tiers.
- **Certificate Chain Transparency**: Complete intermediate and root CA chain inspection, CT log audit verification, and OCSP/CRL revocation checking.
