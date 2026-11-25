# Enterprise SOC & SIEM Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade Fintech Mini-SIEM to a flagship Enterprise SOC & SIEM Web Console with realistic employees/devices, SPL-style search, Employee Device Security dashboard, offline AI Threat Hunt Assistant, full SOAR containment, and EN/RU bilingual support.

**Architecture:** Modular Python application with SQLite persistence, FastAPI web server serving a single-page dark-mode SOC dashboard, offline AI threat hunting, SPL-style search engine, and full bilingual (EN/RU) support.

**Tech Stack:** Python 3.14, SQLite, FastAPI/Uvicorn, rich, pytest, vanilla JavaScript/HTML/CSS/SVG

---

## Global Constraints

- 100% free, zero external API keys, zero cloud dependencies, zero paid services
- Everything runs locally on macOS (Python 3.14) using SQLite, FastAPI, vanilla HTML5/CSS3/SVG/JS
- Zero fake/placeholder names - all employees, devices, hostnames, IPs, cities, emails must be realistically randomized
- Inline HTML/JS template in `src/web_server.py` as raw Python string (`r"""..."""`)
- JavaScript syntax validated with `node --check` in pytest
- 100% offline/local - no external API calls

---

## Phase 1: Database Schema & Models (Employee & Device Tables)

### Task 1: Add Employee & Device Models

**Files:**
- Create: `src/models.py` (extend with Employee, Device dataclasses)
- Modify: `src/__init__.py` (export new models)

**Interfaces:**
- `Employee` dataclass with: employee_id, full_name, email, department, role, employment_type, work_mode, city, country, training_completed, risk_score, status
- `Device` dataclass with: device_id, hostname, employee_id, employee_name, device_type, os_name, employment_type, work_mode, ip_address, city, country, lat, lon, compliance_status, edr_status, isolated

- [ ] **Step 1: Add Employee dataclass** with all required fields
- [ ] **Step 2: Add Device dataclass** with all required fields  
- [ ] **Step 3: Export new models** in `__init__.py`
- [ ] **Step 4: Run tests** to verify models

### Task 2: Add Employee & Device Database Tables

**Files:**
- Modify: `src/storage.py` (add tables, CRUD functions)
- Create: `tests/test_storage_employees.py`

**Interfaces:**
- `init_db()` - creates employees, devices tables
- `seed_realistic_environment(db_path, reset=False)` - creates 75 employees, 110 devices
- `get_employees(db_path)` - returns all employees
- `get_devices(db_path)` - returns all devices with employee join
- `get_employee(employee_id)` - returns single employee
- `get_device(device_id)` - returns single device
- `update_device_isolation(device_id, isolated)` - toggles device isolation
- `get_fleet_posture(db_path)` - returns compliance breakdown, fleet KPIs, geo nodes
- `isolate_device(device_id, reason, performed_by)` - isolates device + audit log
- `unisolate_device(device_id, performed_by)` - unisolates device + audit log

- [ ] **Step 1: Add employees table schema** with all required columns
- [ ] **Step 2: Add devices table schema** with all required columns
- [ ] **Step 3: Implement seed_realistic_environment()** with 75 employees, 110 devices
- [ ] **Step 4: Implement all CRUD functions** for employees and devices
- [ ] **Step 5: Implement fleet posture analytics** (compliance breakdown, fleet KPIs, geo nodes)
- [ ] **Step 6: Implement device isolation/quarantine** with audit logging
- [ ] **Step 7: Write comprehensive tests** for all new functions
- [ ] **Step 8: Run tests** to verify

### Task 3: Enhanced Traffic Generator with Realistic Employees

**Files:**
- Modify: `scripts/generate_fintech_traffic.py`
- Create: `sample_logs/fintech_stream.jsonl` (regenerated)

**Interfaces:**
- `generate_sample_traffic(count, output_path)` - enhanced with realistic employees
- `seed_realistic_environment(db_path, reset=False)` - reusable generator

**Requirements:**
- 75 randomized employees with diverse international names
- 110 corporate devices with realistic hostnames (FIN-MBP-XXXX, PAY-WIN-XXXX, etc.)
- 75% training completion rate
- Compliance ratios: 58% Compliant, 24% Exceptions, 18% Non-Compliant
- All 6 MITRE ATT&CK attack campaigns tied to real employees/devices
- 2-3 Correlated Incidents generated

- [ ] **Step 1: Create name pools** for diverse international employees
- [ ] **Step 2: Create hostname patterns** (FIN-MBP-XXXX, PAY-WIN-XXXX, SEC-LNX-XXXX, etc.)
- [ ] **Step 3: Implement employee/device generation** with realistic distributions
- [ ] **Step 4: Link attack campaigns** to real generated employees/devices
- [ ] **Step 5: Generate multi-stage attack chains** creating 2-3 correlated incidents
- [ ] **Step 6: Regenerate sample_logs/fintech_stream.jsonl**
- [ ] **Step 7: Test generation** and verify all 6 MITRE rules trigger

---

## Phase 2: Backend APIs (SPL Search, Fleet Posture, AI Assistant, SOAR)

### Task 4: SPL-Style Search Engine

**Files:**
- Modify: `src/web_server.py` (add `/api/search` endpoint)

**Interfaces:**
- `GET /api/search?q=...&time_range=...&limit=200`
- Supports: field filters (source_type, status, user, src_ip, hostname, severity, mitre_id)
- SPL pipes: `| stats count by <field1>,<field2>`, `| where count > <N>`
- Returns: `{"total_matched": int, "events": [...], "statistics": [...], "stat_columns": [...]}`

- [ ] **Step 1: Implement SPL parser** for basic query structure
- [ ] **Step 2: Implement field filter parsing** (source_type, status, user, src_ip, hostname, severity, mitre_id)
- [ ] **Step 3: Implement pipe operations** (`stats count by`, `where`)
- [ ] **Step 3: Build query execution** against SQLite events/alerts/incidents
- [ ] **Step 4: Format response** with total_matched, events, statistics, stat_columns
- [ ] **Step 5: Add tests** for SPL queries

### Task 5: Fleet Posture API

**Files:**
- Modify: `src/web_server.py` (add `/api/fleet` endpoint)

**Interfaces:**
- `GET /api/fleet`
- Returns: compliance_breakdown, fleet_kpis, geo_nodes, devices (full list with employee join)

- [ ] **Step 1: Implement `/api/fleet` endpoint**
- [ ] **Step 2: Return compliance breakdown** with counts and percentages
- [ ] **Step 3: Return fleet KPIs** (employee_office, contingent_office, employee_remote, contingent_remote, total_devices, training_completion_pct)
- [ ] **Step 4: Return geo_nodes** with city/country device & alert coordinates
- [ ] **Step 5: Return full device list** with employee join
- [ ] **Step 6: Add tests**

### Task 6: Offline AI Threat Hunt Assistant

**Files:**
- Modify: `src/web_server.py` (add `/api/ai-hunt` endpoint)
- Create: `src/ai_hunt.py` (offline AI engine)

**Interfaces:**
- `POST /api/ai-hunt` with `{"prompt": "...", "lang": "en"|"ru"}`
- Parses intent from English/Russian prompts
- Executes live SQLite queries
- Returns: spl_query, summary (EN/RU), findings, recommended_actions (SOAR buttons)

**Supported intents:**
- Brute-force & credential stuffing hunt
- Impossible travel & account takeover
- Non-compliant devices audit
- High-value payment fraud hunt
- Executive security posture brief

- [ ] **Step 1: Create `src/ai_hunt.py`** with offline intent parser
- [ ] **Step 2: Implement English prompt parsing** for all 5 hunt types
- [ ] **Step 3: Implement Russian prompt parsing** for all 5 hunt types
- [ ] **Step 4: Implement SQL query execution** for each hunt type
- [ ] **Step 5: Generate bilingual summaries** with real employee/device data
- [ ] **Step 6: Generate SOAR action recommendations** with inline buttons
- [ ] **Step 7: Add `/api/ai-hunt` endpoint**
- [ ] **Step 8: Add tests** for EN/RU prompts

### Task 7: Extended SOAR Containment Actions

**Files:**
- Modify: `src/storage.py`, `src/soar.py`, `src/web_server.py`

**Interfaces:**
- `POST /api/soar/isolate-device` - isolates device + audit log
- `POST /api/soar/unisolate-device` - unisolates device + audit log
- `POST /api/simulate` - supports `regenerate_random_all` scenario

- [ ] **Step 1: Add isolate_device/unisolate_device** to storage.py with audit logging
- [ ] **Step 2: Add soar.isolate_device/unisolate_device** functions
- [ ] **Step 3: Add `/api/soar/isolate-device` and `/api/soar/unisolate-device` endpoints**
- [ ] **Step 4: Update `/api/simulate`** to support `regenerate_random_all`
- [ ] **Step 5: Add tests** for new SOAR actions

---

## Phase 3: Frontend - Enterprise SOC Console UI

### Task 8: Enterprise Navigation Bar & Layout

**Files:**
- Modify: `src/web_server.py` (WEB_PAGE template)

**Requirements:**
- Brand logo + ENTERPRISE SOC label
- Live DB indicator
- Language switcher (EN | RU) with localStorage persistence
- Time Range Selector (All time, 15m, 1h, 24h)
- "New Random Data" button (regenerate_random_all)
- Auto-Refresh toggle (5s)
- Export JSON/CSV buttons
- 6 tabs: Alerts & Triage, Search & Analytics, Employee & Device Security, SOC AI Assistant, Incidents, SOAR Center & Simulator

- [ ] **Step 1: Build Enterprise Navigation Bar** with all required elements
- [ ] **Step 2: Implement Language Switcher** with localStorage persistence
- [ ] **Step 3: Implement Time Range Selector** 
- [ ] **Step 4: Add New Random Data button** calling regenerate_random_all
- [ ] **Step 5: Add Auto-Refresh toggle** and Export buttons
- [ ] **Step 6: Create 6-tab layout** structure

### Task 9: Alerts & Triage Tab (SOC Overview)

**Requirements:**
- 6 KPI cards (Total Events, Critical Alerts, High Alerts, Active Incidents, Blocked IPs / Isolated Devices, Mean Risk Score)
- Filter bar (Severity, Status, instant search by employee/hostname/IP/MITRE ID)
- Interactive Alerts Table with real Employee Name, Device Hostname, MITRE ID, Rule, Severity, Risk, Status, Source IP
- Inline action buttons: Investigate, Resolve, Block IP, Freeze User, Isolate Device

- [ ] **Step 1: Build 6 KPI card layout**
- [ ] **Step 2: Build filter bar** with severity, status, search
- [ ] **Step 3: Build enhanced alerts table** with employee name, hostname, MITRE ID
- [ ] **Step 3: Add inline action buttons** with toast feedback
- [ ] **Step 4: Connect all buttons** to API endpoints with toast feedback

### Task 10: Search & Analytics Tab (Splunk SPL)

**Requirements:**
- Monospace SPL query editor with green Search button
- SPL Preset Chips (one-click presets)
- Sub-tabs: Events (expandable JSON), Statistics (grouped count table with bars), Visualization (inline SVG bar charts)
- Statistics table: grouped count with visual bar indicators, sortable headers

- [ ] **Step 1: Build SPL query editor** with monospace font
- [ ] **Step 2: Add SPL Preset Chips** (one-click)
- [ ] **Step 3: Build 3 sub-tabs** (Events, Statistics, Visualization)
- [ ] **Step 4: Implement Statistics table** with bars and sorting
- [ ] **Step 3: Implement Events tab** with expandable JSON
- [ ] **Step 4: Implement Visualization tab** with inline SVG bar charts
- [ ] **Step 5: Connect to `/api/search`** endpoint

### Task 11: Employee & Device Security Tab (Fleet Posture)

**Requirements:**
- Device Compliance Donut Chart (inline SVG ring - clickable slices filter table)
- 4 Fleet Category Cards with +/- trend badges
- Security Training Completion Bar (0-100% gauge) + Total Devices badge
- Interactive SVG World Map with regional bubbles and alert hotspots
- Searchable/filterable Employee & Device Inventory Table with Isolate/Quarantine buttons

- [ ] **Step 1: Build Device Compliance Donut Chart** (inline SVG, clickable)
- [ ] **Step 2: Build 4 Fleet Category Cards** with trend badges
- [ ] **Step 3: Build Training Completion Gauge** + Total Devices badge
- [ ] **Step 4: Build Interactive SVG World Map** with geo bubbles
- [ ] **Step 4: Build Employee & Device Inventory Table** with inline Isolate buttons
- [ ] **Step 5: Connect all components** to `/api/fleet` endpoint

### Task 12: SOC AI Assistant Tab (Threat Hunting)

**Requirements:**
- Split layout: Left sidebar with saved hunt sessions, Main chat stream
- Chat stream: user prompts, collapsible SPL trace, Markdown SOC analysis, inline SOAR buttons
- Bottom prompt input + quick prompt suggestions (EN/RU)
- Language-aware responses (EN/RU)

- [ ] **Step 1: Build split layout** (sidebar + chat)
- [ ] **Step 2: Build saved hunt sessions sidebar**
- [ ] **Step 3: Build chat stream** with SPL trace blocks
- [ ] **Step 4: Render Markdown SOC analysis** with real data
- [ ] **Step 4: Add inline SOAR buttons** in chat responses
- [ ] **Step 5: Build prompt input** with quick suggestions (EN/RU)
- [ ] **Step 6: Connect to `/api/ai-hunt`** endpoint

### Task 13: Incidents Tab (Kill-Chain View)

**Requirements:**
- Multi-stage correlated incident cards
- Chronological attack timeline (Recon -> Brute Force -> Impossible Travel -> High-Value Transfer)

- [ ] **Step 1: Build incident card layout** with timeline
- [ ] **Step 2: Visualize attack chain** with MITRE technique labels

### Task 14: SOAR Center & Simulator Tab

**Requirements:**
- Active Blocked IPs, Frozen Accounts, Isolated Devices (with Unblock/Unfreeze/Restore)
- Immutable Audit Log
- Attack Simulator cards (individual scenarios + regenerate_random_all)

- [ ] **Step 1: Build Blocked IPs / Frozen Accounts / Isolated Devices panels**
- [ ] **Step 2: Build Audit Log table**
- [ ] **Step 3: Build Attack Simulator** with individual scenario buttons
- [ ] **Step 4: Add "New Random Data" button** for regenerate_random_all

---

## Phase 4: Bilingual Support (EN/RU)

### Task 15: Complete I18N Dictionary

**Files:**
- Modify: `src/web_server.py` (add I18N dictionary)

**Requirements:**
- Complete translation dictionary for every UI string
- EN/RU translations for: tabs, KPI cards, SPL elements, Employee Device Security charts/tables, SOC AI presets & reports, status badges, SOAR buttons, toast notifications
- Instant language switch without reload
- localStorage persistence

- [ ] **Step 1: Create complete I18N dictionary** with all translations
- [ ] **Step 2: Implement language switcher** with localStorage
- [ ] **Step 3: Apply translations** to all UI elements in JavaScript
- [ ] **Step 4: Ensure AI Assistant** responds in selected language

---

## Phase 5: Testing & Verification

### Task 16: Database Seeding & End-to-End Tests

**Files:**
- Modify: `tests/test_web_server.py`, `tests/test_mini_siem.py`
- Create: `tests/test_ai_hunt.py`

**Tests:**
- `seed_realistic_environment()` runs on `data/siem.db` at startup
- `/api/search` - SPL queries, pipes, filters
- `/api/fleet` - compliance, KPIs, geo nodes, device list
- `/api/ai-hunt` - both EN and RU prompts
- `/api/soar/isolate-device` - isolation + audit log
- `node --check` on rendered inline JavaScript
- `pytest tests/ -v -k "not generate"` - 100% pass rate

- [ ] **Step 1: Update test_web_server.py** with new endpoint tests
- [ ] **Step 2: Add test_ai_hunt.py** for EN/RU prompt testing
- [ ] **Step 3: Add node --check test** for JS syntax validation
- [ ] **Step 4: Ensure database seeding** runs on startup
- [ ] **Step 5: Run full test suite** and verify 100% pass rate

---

## Phase 6: Final Polish

### Task 17: Final Integration & Documentation

- [ ] **Step 1: Run full integration test** - ingest sample logs, verify all components
- [ ] **Step 2: Verify EN/RU switching** works instantly
- [ ] **Step 3: Verify all 6 MITRE rules** trigger with realistic employees
- [ ] **Step 4: Verify 2-3 Correlated Incidents** generated
- [ ] **Step 4: Update README.md** with new features
- [ ] **Step 5: Final test run** - `pytest tests/ -v -k "not generate"` 100% pass

---

## Review Focus

- SPL search correctly parses and executes complex queries with pipes
- Employee/Device data is truly randomized (no placeholder names like "victim_user")
- AI Hunt Assistant generates accurate bilingual summaries with real employee names
- Device isolation works end-to-end with audit logging
- SVG charts (donut, world map, bars) render correctly and are interactive
- EN/RU switching is instant with no reload
- All 6 MITRE ATT&CK rules trigger correctly
- 2-3 correlated incidents are generated
- 100% test pass rate

---

## Dependencies

- No new external dependencies - all standard library + existing (fastapi, uvicorn, rich, pytest)
- Node.js required only for `node --check` in tests (already available)

---

## Timeline Estimate

This is a substantial upgrade - estimated 20-30 hours of implementation work across all phases. Each task is designed to be independently testable.

---

## Commit Strategy

Each task should be committed independently with descriptive messages:
- `feat(models): add Employee and Device dataclasses`
- `feat(storage): add employees/devices tables and seeding`
- `feat(collector): realistic employee/device traffic generation`
- `feat(api): SPL-style search engine`
- `feat(api): fleet posture endpoint`
- `feat(api): offline AI threat hunt assistant`
- `feat(soar): device isolation containment`
- `feat(ui): enterprise navigation bar`
- `feat(ui): alerts & triage tab`
- `feat(ui): search & analytics tab`
- `feat(ui): employee device security tab`
- `feat(ui): SOC AI assistant tab`
- `feat(ui): incidents kill-chain tab`
- `feat(ui): SOAR center tab`
- `feat(i18n): complete EN/RU localization`
- `test: comprehensive endpoint and JS syntax tests`