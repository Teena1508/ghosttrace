# GhostTrace — Defensive Forensic Investigation & Attack Reconstruction Platform

GhostTrace is a defensive cybersecurity investigation platform designed to reconstruct probable attack timelines and entity relationship graphs from simulated security telemetry.

> **Defensive Security & Simulation Notice**: GhostTrace operates exclusively within simulated environments using fictional benchmark telemetry (RFC 5737 documentation IP ranges, simulated workstations, and synthetic audit logs). It does not connect to production networks or execute containment actions.

---

## Architecture & Project Structure

The project is structured into distinct, modular layers establishing a forensic pipeline from log ingestion to timeline reconstruction:

```
ghost/
├── backend/                        # FastAPI application layer
│   ├── app/
│   │   ├── api/                    # Endpoint routers: health, events, investigations (/reconstruct)
│   │   ├── core/                   # Configuration, CORS, environment settings
│   │   ├── models/                 # API response envelopes & re-exported schemas
│   │   └── main.py                 # FastAPI application factory & server entrypoint
│   └── requirements.txt            # Python dependencies
├── investigation_engine/           # Core forensic logic & investigation graph
│   ├── graph/                      # NetworkX MultiDiGraph & Cytoscape.js serializer
│   ├── correlation.py              # Shared identifier correlation (sessions, processes, IPs)
│   ├── reconstruction.py           # Attack timeline reconstruction & competing hypotheses
│   ├── loader.py                   # JSON fixture loader preserving chain of custody
│   ├── models.py                   # Canonical SecurityEvent schema (Pydantic v2)
│   └── validation.py               # Schema, timestamp, deduplication, & malformed parser
├── data/
│   └── fixtures/
│       ├── simulated_events.json   # Fictional benchmark logs (routine & suspicious)
│       └── malformed_test_cases.json # Edge-case records for parser robustness tests
├── frontend/                       # Modern React + TypeScript + Vite UI
│   ├── src/
│   │   ├── components/             # Cytoscape graph canvas, evidence modal, & reconstruction view
│   │   ├── services/               # Typed backend API client
│   │   ├── types/                  # Shared TypeScript event & reconstruction schemas
│   │   ├── App.tsx                 # SOC/DFIR investigation dashboard
│   │   └── index.css               # Modern dark-mode cybersecurity design system
│   ├── package.json
│   └── vite.config.ts              # Vite config with backend proxy
├── tests/                          # Automated Pytest suite (unit & API)
│   ├── conftest.py                 # TestClient fixture and mock data
│   ├── api/                        # Health, events, and investigation reconstruction API tests
│   └── unit/                       # Schema, validation, correlation, reconstruction, & fixture tests
├── pytest.ini                      # Pytest paths and configuration
└── README.md
```

---

## Key Design Decisions

1. **Evidence Provenance & Immutability (`original_event_data` & `source_event_id`)**:
   - In digital forensics and incident response (DFIR), every finding must be traceable to raw evidence without alteration.
   - The canonical `SecurityEvent` schema mandates preserving the unaltered originating payload in `original_event_data` and tracks the originating identifier in `source_event_id`.

2. **Strict Shared Event Schema with Flexible Parsing**:
   - The canonical schema defines mandatory fields (`event_id`, `timestamp`, `event_type`, `source`, `original_event_data`).
   - Unavailable context fields (`host_id`, `user_id`, `source_ip`, `session_id`, `process_id`, `file_path`, etc.) are optional and default to `None`.
   - The timestamp validator transparently handles ISO 8601 strings (UTC 'Z' and arbitrary timezone offsets), numeric UNIX epoch seconds, and millisecond timestamps, normalizing all internal representations to timezone-aware UTC `datetime`.

3. **Multi-Stage Telemetry Modeling (NetworkX + Cytoscape.js)**:
   - Events and entities (Hosts, Users, Processes, Files, IP addresses) are modeled as a directed multi-graph using NetworkX (`nx.MultiDiGraph`).
   - The graph engine exports directly to standard Cytoscape.js JSON elements (`nodes` and `edges` groups with relationship attributes), allowing the React frontend to render interactive forensic graphs with zero schema translation overhead.

4. **Robust Malformed Record and Duplicate Handling**:
   - The validation pipeline detects non-dict primitives, broken JSON strings, missing required fields, unparseable dates, duplicate `event_id` keys, and duplicate source telemetry pairs `(source, source_event_id)`.
   - Batch validation returns granular error diagnostics without crashing the telemetry ingestion pipeline.

---

## Canonical Security Event Schema

| Field | Type | Description |
|---|---|---|
| `event_id` | `string` (Required) | Unique canonical event identifier |
| `timestamp` | `ISO 8601 / datetime` (Required) | Normalized UTC timestamp |
| `event_type` | `enum` (Required) | `AUTHENTICATION`, `PROCESS_EXECUTION`, `FILE_AUDIT`, `NETWORK_CONNECTION` |
| `severity` | `enum` (Required) | `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `source` | `string` (Required) | Originating telemetry source (e.g. `simulated_auditd`, `simulated_zeek`) |
| `original_event_data` | `object` (Required) | Preserved unaltered raw log record |
| `source_event_id` | `string` (Optional) | Telemetry stream native ID (fallback to record ID or event_id) |
| `host_id` | `string` (Optional) | Hostname / server identifier |
| `user_id` | `string` (Optional) | Principal / username |
| `source_ip` | `string` (Optional) | Originating IP address |
| `destination_ip` | `string` (Optional) | Target IP address |
| `destination_port`| `integer` (Optional) | Target network port |
| `session_id` | `string` (Optional) | Correlation / logon session identifier |
| `process_id` | `int / string` (Optional) | Process ID |
| `process_name` | `string` (Optional) | Executable name |
| `command_line` | `string` (Optional) | Executed command line |
| `file_path` | `string` (Optional) | Path to accessed or modified file |
| `action` | `string` (Optional) | Forensic action tag (e.g. `LOGON_SUCCESS`, `FILE_READ`) |
| `is_suspicious` | `boolean` (Optional) | Benchmark ground-truth label (routine vs suspicious) |
| `mitre_attack_id`| `string` (Optional) | Simulated MITRE ATT&CK technique reference |

---

## Quick Start & Setup

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 2. Backend Setup & Run

Install Python dependencies (if in a virtual environment or system Python):
```bash
pip install -r backend/requirements.txt
```

Start the FastAPI backend server:
```bash
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI documentation is available at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
- **Investigation Reconstruction**: `POST /api/investigations/reconstruct` or `POST /api/v1/investigations/reconstruct`

#### Example Reconstruction API Call
```bash
curl -X POST "http://localhost:8000/api/investigations/reconstruct" \
     -H "Content-Type: application/json" \
     -d '{
       "events": [
         {
           "event_id": "auth-1",
           "timestamp": "2026-10-18T09:12:01Z",
           "event_type": "AUTHENTICATION",
           "host_id": "corp-app01.sim.local",
           "user_id": "svc_deploy",
           "source_ip": "198.51.100.42",
           "severity": "MEDIUM",
           "source": "simulated_auth_log",
           "action": "LOGON_FAILURE",
           "is_suspicious": true,
           "original_event_data": {"record": 99014}
         },
         {
           "event_id": "auth-2",
           "timestamp": "2026-10-18T09:12:45Z",
           "event_type": "AUTHENTICATION",
           "host_id": "corp-app01.sim.local",
           "user_id": "svc_deploy",
           "source_ip": "198.51.100.42",
           "session_id": "sess-compromised-99",
           "severity": "HIGH",
           "source": "simulated_auth_log",
           "action": "LOGON_SUCCESS",
           "is_suspicious": true,
           "original_event_data": {"record": 99018}
         }
       ],
       "deduplicate": true
     }'
```

### 3. Frontend Setup & Run

In a separate terminal, navigate to the frontend directory:
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser. The Vite development server automatically proxies `/api` and `/health` requests to the FastAPI backend at `http://localhost:8000`.

To build the frontend for production:
```bash
cd frontend
npm run build
```

---

## Running the Automated Test Suite

GhostTrace includes a comprehensive test suite covering schema validation, flexible timestamp parsing, duplicate detection, malformed records, fixture integrity, graph serialization, and API endpoints.

Run tests using Pytest:
```bash
python3 -m pytest tests
```

To run with verbose output:
```bash
python3 -m pytest -v
```

### Test Coverage Highlights
- `tests/unit/test_schemas.py`: Verifies required and optional fields, enum checking, fallback ID extraction, and timestamp parsers (ISO 8601 with Z, offsets, Unix timestamps in seconds/ms, and error handling for bad strings).
- `tests/unit/test_validation.py`: Tests duplicate detection (by `event_id` and `source_event_id`), deduplication toggles, null/non-dict records, and verifies the fixture `data/fixtures/malformed_test_cases.json`.
- `tests/unit/test_fixtures.py`: Confirms that `data/fixtures/simulated_events.json` validates with 0 errors, covers all 4 event types, contains both routine and suspicious activity, preserves provenance, and constructs valid NetworkX / Cytoscape elements.
- `tests/api/test_health.py`: Validates `/health` and `/api/v1/health` status codes, versioning, and engine readiness.
- `tests/api/test_events_api.py`: Validates event querying, suspicious filtering, category filtering, NetworkX graph element serialization, and the `/api/v1/events/validate` endpoint.
