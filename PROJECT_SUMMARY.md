# ThreatLens (TRACEPOINT) — Project Description & Complete Summary

## 1. Project Description

**ThreatLens** (powered by the **TRACEPOINT** engine) is a full-stack **Security Log Analyzer and Explainable Attack Chain Reconstruction Platform**. It ingests heterogeneous authentication, web-server, firewall, Windows Security/Sysmon, operating-system/audit, and network egress logs, normalizes them into a canonical event schema, detects threats using both deterministic security rules and Scikit-learn behavioural anomaly detection, correlates related events into multi-stage attack graphs using NetworkX, computes an auditable risk prioritisation score, and lets analysts inspect raw logs, replay attacks step-by-step, query incident evidence, and export reports.

Rather than surfacing isolated alerts, ThreatLens connects the underlying evidence to show **how an attack unfolded**, **which identities or hosts pivoted**, and **why the incident received its risk score**.

---

## 2. Processing Pipeline

```text
LOG INGESTION (File Upload / Raw Paste / Presets / Synthetic Stream)
   │
   ▼
FORMAT ROUTING & PARSERS (SSH, Web, Firewall, Windows Event, OS/Audit, CSV, JSON, TXT)
   │
   ▼
CANONICAL NORMALISATION (UTC ISO-8601, Preserved raw_log, Parse Error Reporting)
   │
   ▼
SQLITE PERSISTENCE (events, findings, incidents, ingestion_batches)
   │
   ▼
HYBRID DETECTION ENGINE
   ├─► Deterministic Rules (Brute Force, Impossible Travel, Unusual Time, Priv-Esc, Sensitive Access, Exfil, Web/Firewall/Audit Tampering)
   └─► Behavioural ML (Scikit-learn Isolation Forest trained on 600-sample normal baseline)
   │
   ▼
NETWORKX CORRELATION & DIRECTED ATTACK GRAPH (User/IP/Host/Session/Resource/External Pivots)
   │
   ▼
DETERMINISTIC RISK SCORING (0–100 Prioritisation Score, Duplicate Suppression, Breakdown)
   │
   ▼
LOG-FIRST THREAT-HUNTER WORKBENCH (Analyze & Ingest · Log Explorer · Threats & Chains · Reports & Query)
```

---

## 3. Technology Stack

### Backend (`backend/requirements.txt`)
- **Python 3.12** & **FastAPI `0.115.6`** + **Uvicorn `0.32.1`**
- **Pydantic `2.10.3`** & **Pydantic Settings `2.6.1`**
- **Pandas `2.2.3`** & **NumPy `2.1.3`**
- **Scikit-learn `1.5.2`** (`IsolationForest`, `StandardScaler`)
- **NetworkX `3.4.2`** (Undirected correlation clustering & directed `DiGraph` attack graphs)
- **SQLite** (`sqlite3` persistence layer)
- **Pytest `8.3.4`** & **HTTPX `0.28.1`**

### Frontend (`frontend/package.json`)
- **React `18.3.1`** & **TypeScript `~5.6.2`**
- **Vite `5.4.11`**
- **Tailwind CSS `3.4.15`**
- **React Flow (`@xyflow/react` `^12.3.5`)** for interactive attack graphs and replay highlighting
- **Recharts `^2.13.3`** for event/failure histograms
- **Lucide React `^0.460.0`** for UI iconography

---

## 4. Repository Structure & File Summary

### Root
- `.env.example` / `backend/.env.example` — Environment configuration template (database path, CORS, rule thresholds, optional LLM API key).
- `README.md` — Quickstart setup and launch guide.
- `PROJECT_SUMMARY.md` — Complete project description and architectural reference.

### Backend (`backend/`)
- `backend/app/main.py` — FastAPI application setup, CORS middleware, DB initialization on startup, and API router mounting.
- `backend/app/config.py` — Runtime `Settings` (detection thresholds, correlation window, risk weights, optional LLM settings).
- `backend/app/schemas/models.py` — Pydantic models (`CanonicalEvent`, `Finding`, `AttackGraph`, `GraphNode`, `GraphEdge`, `RiskScoreBreakdown`, `TimelineEntry`, `IncidentSummary`, `IncidentDetail`, `IngestionReport`, `InvestigationResponse`, etc.).
- `backend/app/database/db.py` — SQLite schema creation (`events`, `findings`, `incidents`, `ingestion_batches`) and CRUD helpers (`init_db`, `reset_db`, `save_events`, `get_all_events`, `replace_findings_and_incidents`, etc.).
- **Parsers (`backend/app/parsers/`):**
  - `router.py` — Format auto-detection (`detect_log_format`) and parser routing (`parse_logs`).
  - `base.py` — `ParseResult` container tracking parsed events and per-line parse errors.
  - `ssh_auth_parser.py` — OpenSSH (`sshd`) and PAM authentication log parser.
  - `web_access_parser.py` — Apache/Nginx Common & Combined log format parser.
  - `firewall_parser.py` — iptables/UFW (`SRC=`, `DST=`, `DPT=`) and Cisco ASA (`%ASA-...`) firewall log parser.
  - `windows_event_parser.py` — Windows Security (`4624`, `4625`, `4648`, `4672`, `4688`, `4720`, `4728`, `4732`, `1102`) and Sysmon (`1`, `3`, `11`) parser.
  - `os_audit_parser.py` — Linux `sudo`, `auditd`, and `netflow` parser with target-user extraction for privilege grants.
  - `csv_parser.py` — Pandas-backed CSV log parser.
  - `json_parser.py` — JSON array, envelope (`{"events": [...]}`), and NDJSON/JSONL parser.
  - `txt_parser.py` — Mixed raw text line-by-line fallback router.
- **Normalisation (`backend/app/normalizer/`):**
  - `canonical.py` — Normalizes heterogeneous timestamps (ISO-8601, Apache, syslog, epoch), maps `source_type` (`auth | web | system | proxy | firewall | windows`) and `status` (`success | failure | unknown`), preserves `raw_log`, and generates `event_id`s.
- **Hybrid Detection (`backend/app/detectors/` & `backend/app/ml/`):**
  - `detectors/rules.py` — Deterministic detectors:
    - `detect_brute_force`
    - `detect_impossible_travel`
    - `detect_unusual_login_time`
    - `detect_privilege_escalation`
    - `detect_sensitive_resource_access`
    - `detect_data_exfiltration`
    - `detect_web_and_perimeter_threats` (SQLi, XSS, path traversal, firewall port scans, Windows EventID 1102 audit log clearing)
  - `ml/anomaly.py` — `BehavioralAnomalyDetector` using `StandardScaler` + `IsolationForest` over 8 hourly per-user features (`login_frequency`, `failed_login_ratio`, `unique_ip_count`, `unique_resource_count`, `outbound_bytes`, `activity_hour`, `session_frequency`, `unusual_resource_access`) with statistical z-score feature explanations.
- **Correlation, Graph, Scoring & Reconstruction:**
  - `correlation/engine.py` — NetworkX correlation clustering (`correlate_findings`) linking events by identity pivots (`target_user -> user`), shared `user`, shared external/network IP, shared `session_id`, shared `hostname + pid`, or shared `hostname + resource` within `correlation_window_minutes`.
  - `graph/builder.py` — Directed `nx.DiGraph` attack graph builder (`build_attack_graph`) creating typed entity/event nodes and edges (`AUTHENTICATED_FROM`, `PERFORMED`, `EXECUTED`, `ESCALATED_TO`, `ACCESSED`, `TRANSFERRED_TO`, `CORRELATED_WITH`).
  - `scoring/engine.py` — Deterministic risk scorer (`calculate_risk_score`) with configurable weights, duplicate suppression per category, 0–100 capping, and severity classification.
  - `incidents/reconstructor.py` — End-to-end orchestrator (`run_detection_and_reconstruction`) generating `IncidentDetail` objects, chronological `TimelineEntry` replay steps, and evidence-cited `summary_claims`.
- **Analyzer Summary, Export & Assistant:**
  - `analyzer/summary.py` — IOC extraction, top source IP / user / host / resource aggregations (`build_analyzer_summary`), 4 one-click `SAMPLE_PRESETS`, and Markdown/JSON/CSV report exporter (`export_report`).
  - `assistant/investigator.py` — Grounded Investigation Assistant (`answer_investigation_question`) with deterministic offline retrieval and optional env-configured LLM synthesis.
- **API, Data & Tests:**
  - `api/routes.py` — FastAPI REST endpoints under `/api`.
  - `data/generate_demo.py` — Deterministic synthetic generator (`seed=2026`) producing 1,188 mixed events (`synthetic_demo_logs.jsonl`).
  - `tests/test_pipeline.py` — Automated unit and end-to-end integration test suite.

### Frontend (`frontend/src/`)
- `App.tsx` — Threat-Hunter Dark (`#09090b`) top-navigation shell with 4 log-first tabs and live event/finding counters.
- `pages/AnalyzeWorkbenchPage.tsx` — Drag-and-drop multi-format uploader, raw log paste console, 1-click sample presets (`ssh_intrusion`, `web_sqli`, `firewall_scan`, `windows_ad`, and 1,188-event Enterprise Demo), parse health & skipped-line warnings, and telemetry summary.
- `pages/LogExplorerPage.tsx` — Recharts hourly event/failure bar chart, source-type filter pills, `.* Regex` search toggle, outcome filter, dense event table, and Parsed Fields & Raw Line Inspector.
- `pages/ThreatsChainsPage.tsx` — Extracted IOCs, Top Source IPs & Top Accounts, Rule & ML Findings list, and Correlated Attack Chains with interactive **Attack Replay** (`Play/Pause/Prev/Next`) and **Full Graph & Score** view.
- `pages/ReportsQueryPage.tsx` — 1-click Markdown/JSON/CSV report export, evidence-grounded Incident Query assistant, detection threshold tuning, and ML retraining controls.
- `components/AttackGraphCanvas.tsx` — Interactive React Flow attack graph with distinct Event vs Entity nodes, edge correlation inspector, and replay step highlighting.
- `components/ScoreBreakdownPanel.tsx` — Visual segmented risk score bar and per-detector contribution audit list.
- `services/api.ts`, `types/tracepoint.ts`, `utils/format.ts` — Typed REST client, TypeScript interfaces, and formatting helpers.

---

## 5. REST API Reference

| Method & Endpoint | Purpose |
|---|---|
| `GET /api/health` | Service health check |
| `POST /api/logs/upload` | Upload log file (`multipart/form-data`) and run full pipeline |
| `POST /api/logs/analyze` | Ingest raw pasted log text and run full pipeline |
| `GET /api/logs` | Search/filter canonical logs (`source_type`, `user`, `src_ip`, `status`, `incident_id`, `q`, `regex`, `limit`, `offset`) |
| `GET /api/incidents` | List reconstructed incident summaries |
| `GET /api/incidents/{incident_id}` | Retrieve full incident detail (timeline, graph, findings, score breakdown) |
| `GET /api/incidents/{incident_id}/timeline` | Retrieve chronological attack replay timeline |
| `GET /api/incidents/{incident_id}/graph` | Retrieve directed attack graph nodes and edges |
| `GET /api/incidents/{incident_id}/evidence` | Retrieve supporting findings, canonical events, and score claims |
| `GET /api/findings` | List rule and ML findings (`detection_source`, `category`, `severity`, `incident_id`) |
| `GET /api/metrics` | Live telemetry counts, hourly series, severity distribution, and ML baseline stats |
| `POST /api/investigate` | Ask grounded investigation questions about an incident |
| `POST /api/demo/load` | Reset DB and load the 1,188-event synthetic enterprise dataset |
| `POST /api/demo/reset` | Clear SQLite tables and reset ML baseline |
| `GET /api/settings` / `PUT /api/settings` | Read or update detection/correlation/scoring thresholds and recompute |
| `POST /api/ml/retrain` | Retrain Isolation Forest on baseline + clean observed events |
| `GET /api/analyzer/summary` | Retrieve IOCs, top source IPs, top accounts, and entity breakdowns |
| `GET /api/analyzer/presets` | List built-in sample log scenarios |
| `POST /api/analyzer/presets/{preset_id}` | Reset and ingest a sample scenario (`ssh_intrusion`, `web_sqli`, `firewall_scan`, `windows_ad`) |
| `GET /api/analyzer/export` | Download report as `markdown`, `json`, or `csv` |

---

## 6. Synthetic Demo Scenario (`INC-2026-041`)

Loading the synthetic enterprise dataset (`POST /api/demo/load`) generates **1,188 mixed events** (corporate SSH, web, OS audit, and netflow baselines plus injected attack stages) and dynamically reconstructs **`INC-2026-041`** with a prioritisation score of **96/100 (Critical)**:

1. **`14:02:11Z` — Credential Brute Force (`+25`):** 32 failed SSH login attempts against `admin_01` from `185.220.101.4` within 86 seconds.
2. **`14:04:03Z` — Suspicious Authentication / Impossible Travel (`+20`):** Successful login as `admin_01` from `185.220.101.4` (`Frankfurt, DE`) following an earlier `13:10:00Z` session from `Bengaluru, IN`.
3. **`14:07:19Z` — Privilege Escalation & Identity Pivot (`+25`):** `admin_01` executes `sudo /usr/sbin/usermod -aG wheel,backup_ops svc_backup`, creating an explicit `ESCALATED_TO` edge to `svc_backup`.
4. **`14:09:44Z` — Sensitive Resource Access (`+15`):** `svc_backup` reads `/var/secure/payroll_export.csv`.
5. **`14:11:30Z` — Data Exfiltration (`+11`):** `svc_backup` transfers `418.0 MB` outbound to `185.220.101.4` against a `3.8 MB` baseline.

---

## 7. Running Locally & Testing

### Start Backend
```powershell
cd backend
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Start Frontend
```powershell
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173/`.

### Run Automated Tests
```powershell
backend\.venv\Scripts\python -m pytest backend\tests\test_pipeline.py -v
```
