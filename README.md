# Fintech Mini-SIEM & SOAR Web Console

A production-grade, 100% offline-capable Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform for fintech environments.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    fintech-mini-siem                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │
│  │   CLI Tool  │  │  WEB UI    │  │  TRAFFIC   │                   │
│  │   (Rich)    │  │  (Dark Mode)│ │ GENERATOR  │                   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                   │
│         │                │                │                          │
│         └────────────────┼────────────────┘                          │
│                            │                                           │
│                      ┌────▼────┐                                        │
│                      │   API   │  FastAPI REST API                     │
│                      │ SERVER  │                                        │
│                      └────┬────┘                                        │
│                           │                                           │
│  ┌─────────────┐   ┌─────▼────────────────┐   ┌─────────────┐       │
│  │COLLECTOR    │   │    ENGINE            │   │  SOAR       │       │
│  │(Log Parsing)│──▶│(Detection &        │──▶│(Automation) │       │
│  │             │   │ Correlation)        │   │             │       │
│  └─────────────┘   └─────┬────────────────┘   └─────┬───────┘       │
│                          │                              │             │
│                    ┌─────▼──────┐              ┌────────▼────────┐     │
│                    │ STORAGE    │              │ THREAT INTEL    │     │
│                    │ (SQLite)   │              │ (Offine IOC)    │     │
│                    └────────────┘              └─────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

### Multi-Source Log Ingestion
- **Auth Service logs**: Login events, MFA challenges, password resets
- **API Gateway logs**: REST endpoints, HTTP status codes, User-Agents
- **Payment Engine logs**: Card/P2P transfers, amounts, currency

### Offline Threat Intelligence
- Local IOC database (no external API calls)
- Malicious IP detection (including Tor exit nodes, datacenter ranges)
- Suspicious User-Agent detection (sqlmap, nikto, gobuster, etc.)
- Disposable email/card BIN pattern matching

### Detection Rules (MITRE ATT&CK)
| Rule | ID | Description | Severity |
|------|-----|-------------|----------|
| T1110.001 | Brute-Force Login | 5+ failed logins from same IP/user in 60s | HIGH |
| T1110.003 | Password Spraying | 6+ failed logins across 4+ users from same IP in 5m | HIGH |
| T1078 | Impossible Travel | 2 logins from different countries for same user in 60m | CRITICAL |
| T1595.003 | API Endpoint Enumeration | 15+ 403/404 errors from same IP in 60s | MEDIUM |
| T1190 | API Injection Probe | SQLi, path traversal, JWT/IDOR patterns | HIGH |
| T1078-T1657 | Multi-Stage Account Takeover | Correlation of brute-force + high-value transfer | CRITICAL |

### Automated SOAR Playbooks
- `block_ip`: Add IP to local blocklist
- `freeze_account`: Freeze user account
- `revoke_sessions`: Log session revocation
- Full audit trail with timestamps

### Dark-Mode SOC Dashboard
- Real-time KPIs and alerts
- MITRE ATT&CK technique breakdown
- Interactive filtering and search
- One-click response actions

## Quick Start

### Prerequisites
- Python 3.14+
- pip (Python package manager)

### Installation

```bash
# Clone and install
cd fintech-mini-siem
pip install -e .

# Or install dependencies directly
pip install fastapi uvicorn rich pytest

# Initialize database
python -m src.cli init
```

### CLI Usage

```bash
# Initialize database
python -m src.cli init

# Ingest logs
python -m src.cli ingest sample_logs/fintech_stream.jsonl

# View alerts
python -m src.cli alerts

# View incidents
python -m src.cli incidents

# Start web dashboard
python -m src.cli serve --port 8080

# Execute SOAR action
python -m src.cli respond block_ip 192.168.1.100 --reason "Malicious activity" --analyst "analyst1"

# Export incident report
python -m src.cli export --format json --output incident_report

# Simulate attack scenarios
python -m src.cli simulate
```

### Web Dashboard

Open http://127.0.0.1:8080 in your browser.

Features:
- **Live Alerts**: Filter by severity, status, MITRE ID
- **Incidents**: View correlated attack timelines
- **SOAR Center**: Manage blocked IPs, frozen accounts
- **Simulator**: Generate test attack traffic

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_engine.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

## Sample Data Generation

```bash
# Generate realistic fintech traffic
python -c "from src.collector import generate_sample_traffic; generate_sample_traffic(500)"

# Files created:
# - sample_logs/fintech_stream.jsonl (mixed normal + attack traffic)
# - sample_logs/test_traffic.jsonl (for testing)
```

## Project Structure

```
fintech-mini-siem/
├── src/
│   ├── __init__.py
│   ├── models.py            # Core dataclasses
│   ├── collector.py         # Log ingestion & normalization
│   ├── storage.py           # SQLite persistence
│   ├── enrichment.py        # Offline threat intel
│   ├── engine.py            # Detection & correlation
│   ├── soar.py              # Automated responses
│   ├── web_server.py        # FastAPI server
│   ├── cli.py               # Rich CLI interface
│   └── reporter.py          # Terminal report generation
├── rules/
│   └── detection_rules.json # MITRE ATT&CK rules
├── threat_intel/
│   └── local_iocs.json      # Offline IOC feeds
├── scripts/
│   └── generate_fintech_traffic.py
├── sample_logs/
│   ├── fintech_stream.jsonl
│   └── test_traffic.jsonl
├── tests/
│   ├── test_models.py
│   ├── test_collector.py
│   ├── test_storage.py
│   ├── test_enrichment.py
│   ├── test_engine.py
│   ├── test_soar.py
│   └── test_reporter.py
├── .gitignore
├── requirements.txt
├── pyproject.toml
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Dashboard HTML |
| GET | /api/stats | KPI statistics |
| GET | /api/alerts | Filtered alerts (supports query params) |
| GET | /api/incidents | All incidents |
| GET | /api/soar | SOAR status |
| POST | /api/respond | Execute SOAR action |
| POST | /api/simulate | Run attack simulation |
| POST | /api/block-ip | Block IP address |
| POST | /api/unblock-ip | Unblock IP |
| POST | /api/freeze-account | Freeze user account |

## Database Schema

- **events**: Raw normalized events
- **alerts**: Generated security alerts
- **incidents**: Correlated multi-stage incidents
- **incident_timeline**: Attack step timeline
- **entity_risk_scores**: User/IP risk scores
- **audit_log**: Analyst/SOAR action log
- **blocked_ips**: IP blocklist
- **frozen_accounts**: Frozen user accounts

## Offline Capabilities

This SIEM operates 100% offline:
- All threat intelligence is embedded locally
- SQLite is the only database (no network dependencies)
- Web dashboard serves static HTML/JS (no CDN)
- No external API calls required

## License

MIT License - Free for personal and commercial use.
