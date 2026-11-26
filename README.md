# TRACEPOINT — Explainable Attack Investigation & Timeline Reconstruction Engine

TRACEPOINT is a full-stack defensive cybersecurity investigation platform that ingests heterogeneous authentication, web-server, OS/audit, and egress logs, detects suspicious activity using deterministic rules + Scikit-learn Isolation Forest behavioural anomaly detection, correlates events into multi-stage attack chains using NetworkX, scores incident priority transparently, and provides interactive **Attack Replay** and an evidence-grounded **Investigation Assistant**.

**Pipeline:**
`LOG INGESTION -> NORMALISATION -> HYBRID DETECTION (RULES + ML) -> EVENT CORRELATION -> ATTACK GRAPH -> RISK SCORING -> INVESTIGATION DASHBOARD`

---

## Architecture

- **Backend (`backend/`):** Python 3.12, FastAPI, Pandas, NumPy, Scikit-learn (`IsolationForest`), NetworkX (`DiGraph`), SQLite, Pydantic.
- **Frontend (`frontend/`):** React, TypeScript, Vite, Tailwind CSS, Recharts, React Flow (`@xyflow/react`), Lucide Icons.

---

## Setup & Launch Commands

### 1. Backend Setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env
```

Start the FastAPI backend:

```powershell
cd backend
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

Open the TRACEPOINT SOC interface at `http://localhost:5173` (API requests proxy automatically to `http://127.0.0.1:8000`).

---

## Automated Tests

Run the unit & end-to-end integration test suite (covering all log parsers, canonical normalisation, deterministic detectors, non-merging of unrelated events, identity pivot reconstruction, risk scoring, and `INC-2026-041` reconstruction):

```powershell
backend\.venv\Scripts\python -m pytest backend\tests\test_pipeline.py -v
```

---

## Demonstrating `INC-2026-041`

1. Launch the backend and frontend.
2. Click **Load Synthetic Demo** (or `POST /api/demo/load`).
3. TRACEPOINT generates and ingests 1,200+ synthetic mixed logs (clearly tagged as synthetic) and dynamically reconstructs **`INC-2026-041` (Risk Score: 96/100, Critical)**:
   - `14:02:11Z` — 32 failed SSH attempts against `admin_01` from `185.220.101.4` (`+25`)
   - `14:04:03Z` — Suspicious login from `185.220.101.4` (`Frankfurt, DE`) vs prior `Bengaluru, IN` session (`+20`)
   - `14:07:19Z` — Privilege escalation: `admin_01` grants elevated permissions to `svc_backup` (`+25`)
   - `14:09:44Z` — `svc_backup` accesses `/var/secure/payroll_export.csv` (`+15`)
   - `14:11:30Z` — `svc_backup` transfers `418.0 MB` outbound vs `3.8 MB` baseline (`+11`)
4. Open **Timeline & Replay** to step through the attack event-by-event on the synchronized React Flow attack graph, inspect supporting raw logs in **Evidence Explorer**, or ask questions in **Investigation Assistant**.
