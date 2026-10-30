# GA5 Incident Agent (`ga5-incident-agent/v2`)

Zero-dependency Node 18+ service. Endpoints:

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET  /v2/incidents/{runId}`

## Layout
| File | Role |
|---|---|
| `src/planner.js` | The only model call (once per first-seen runId). Validates the model's JSON against allowed root causes, evidence IDs, tool schemas. `sensitive` and `doNotExport` are never sent. |
| `src/machine.js` | Receipt-driven state machine: diagnostics, one retry on 503, timeout suppression, approval gate + SHA-256 digest, effect dispatch. No model calls. |
| `src/telemetry.js` | Builds the OTLP trace + response only from stored dispatches/receipts. Deterministic, so replays are identical. |
| `src/store.js` | Atomic JSON-file persistence (written before every response). |
| `src/server.js` | HTTP routing, validation, 400/404/409/422, replay + conflict handling, no input echoed in errors. |

## Run
```bash
cp .env.example .env   # set LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
export $(grep -v '^#' .env | xargs)
npm start
npm test               # offline self-test (mock planner) - uses NO grader checks
```

## Deploy (needs public HTTPS + persistent disk)
- **Render / Railway / Fly.io**: deploy the Dockerfile, set env vars, mount a volume at `/data` (DATA_DIR) so state survives restarts.
- Quick test: `cloudflared tunnel --url http://localhost:8080`.
Submit the base URL with no trailing path, query or credentials. Don't use a host that redirects.

## Design notes
- Replays (same request / same receipt) return the *current stored state* - identical JSON, no model call.
- `dispatches` = calls currently awaiting an outcome; `approvals` = pending approval requests; both empty when final.
- Timeout on a diagnostic -> effect suppressed (`suppressed:[effectTool]`, `chosenEffect:null`, status `failed`).
- The effect (incl. "page owner instead of scaling at limit") is decided in the single planning call, so receipts never need a model.
- Don't burn Checks: run `npm test` locally first (10 checks / 24h, last reserved for Save).
