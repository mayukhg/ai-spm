# Continuous Automated Health & Governance

This document describes the architecture changes that implement the **Continuous Automated Health & Governance** product shape and the **Practical Fast Math vs Flashy LLMs** tradeoff.

## Product intent

| Diagram concept | Implementation in this repo |
| --- | --- |
| Persistent resident agent | `server/governance/resident-agent.ts` — boots with the Node process, 15‑minute timer, **Run now** API/UI |
| Live production pipelines | Synthetic pipeline extracts under `fixtures/synthetic/ticket-training-set-*.csv` (baseline + current) |
| Six dimensions of data quality | Completeness, accuracy, consistency, validity, uniqueness, freshness in `server/analysis/fast-math.ts` |
| Statistical drift | Kolmogorov–Smirnov on `amount` |
| Real-time dashboard | Dashboard metrics + **Health & Governance** page (`/health-governance`) |
| Async GDPR / NIST documents | OpenRouter chat completion → `governance_reports` table; UI lists and displays markdown |

## Architecture rule (non-negotiable)

```
Real-time monitoring  →  Classic statistical / ML only   (target <100ms)
Asynchronous governance →  OpenRouter LLM (gpt-4o-mini)  (latency OK)
```

**LLMs are never called on the resident monitoring path.** Using an LLM for batch quality/drift checks previously created 5–8s latency and token burn; that path is deliberately offloaded to Isolation Forest, LOF, and KS-tests.

## Components added or changed

### 1. Practical Fast Math — `server/analysis/fast-math.ts`

Synchronous, in-process algorithms with no network I/O:

| Method | Role |
| --- | --- |
| `scoreQualityDimensions` | Six quality scores 0–1 |
| `ksDrift` | Two-sample Kolmogorov–Smirnov on amounts |
| `isolationForestScores` | Isolation Forest anomaly scores + flagged indices |
| `localOutlierFactorScores` | Local Outlier Factor (k-neighbors) |
| `runFastMathMonitor` | Full cycle wrapper; returns `elapsedMs` and `withinBudget` |

Both Isolation Forest **and** LOF run on every cycle (approved default).

### 2. Resident agent — `server/governance/resident-agent.ts`

- Interval: **15 minutes** (`INTERVAL_MS`)
- Starts automatically on server listen unless `RESIDENT_AGENT=false`
- On each cycle:
  1. Loads baseline + current CSVs for `ticket-training-set`
  2. Runs `runFastMathMonitor`
  3. Persists six quality metrics, one drift row, two anomaly rows (IF + LOF)
  4. Inserts a `monitoring_cycles` row with timing and JSON result
- Triggers: `scheduled` | `manual` (Run now)

### 3. OpenRouter client — `server/governance/openrouter-client.ts`

- Endpoint: `https://openrouter.ai/api/v1/chat/completions`
- Auth: `OPENROUTER_API_KEY` from local `.env`
- Default model: `openai/gpt-4o-mini` (`OPENROUTER_MODEL`)
- Used **only** by async governance synthesis

### 4. Async compliance reports — `server/governance/async-compliance.ts`

1. Collects recent quality, drift, anomaly, assessment, and cycle evidence from Postgres
2. Creates a `governance_reports` row with `status=running`
3. Calls OpenRouter asynchronously (HTTP returns `202` immediately)
4. Writes markdown body, summary, model, elapsed ms; status `completed` or `failed`

If `OPENROUTER_API_KEY` is missing, the API returns **503** with `needsOpenRouterKey: true` so the UI can prompt the operator.

### 5. Schema — `shared/schema.ts`

New tables:

- `governance_reports` — async LLM narratives
- `monitoring_cycles` — resident agent cycle ledger

Tables are also created at runtime via `CREATE TABLE IF NOT EXISTS` so local Docker Postgres works without a full migrate step.

### 6. HTTP API — `server/routes.ts`

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/governance/health/status` | Agent + OpenRouter status |
| GET | `/api/governance/health/cycles` | Recent cycles |
| POST | `/api/governance/health/run-now` | Manual monitoring cycle |
| POST | `/api/governance/health/start` | Start 15m timer |
| POST | `/api/governance/health/stop` | Stop timer (ciso) |
| GET | `/api/governance/reports` | List reports |
| GET | `/api/governance/reports/:id` | Single report |
| POST | `/api/governance/reports` | Queue async GDPR/NIST report |

### 7. Frontend — `/health-governance`

Page `client/src/pages/health-governance.tsx`:

- Resident agent card with **Run now**
- Async governance card with **Generate GDPR / NIST report**
- OpenRouter key-required banner when the key is missing
- Cycle history and report list with markdown viewer

Sidebar entry: **Health & Governance**.

### 8. Environment

`.env.example` documents:

```bash
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-4o-mini
RESIDENT_AGENT=true
```

`dotenv/config` is loaded at the top of `server/index.ts`. **Do not commit real API keys.**

### 9. Synthetic fixtures

`scripts/seed-synthetic.ts` regenerates ticket CSVs with:

- `timestamp` column for freshness scoring
- Planted high `amount` outliers (last 5 rows) for Isolation Forest / LOF signal
- Baseline mean ~100 vs current mean ~180 for KS drift

## Data flow

```
fixtures/synthetic/*.csv
        │
        ▼
 Resident agent (15m / Run now)
        │
        ├─► fast-math (quality + KS + IF + LOF)   [<100ms target]
        │         │
        │         ▼
        │   data_quality_metrics
        │   data_drift_metrics
        │   data_anomaly_detections
        │   monitoring_cycles
        │
        └─► (no LLM)

Evidence in Postgres ──async──► OpenRouter (gpt-4o-mini)
                                      │
                                      ▼
                              governance_reports
                                      │
                                      ▼
                         Health & Governance UI
```

## Operator runbook

1. Ensure Postgres and `npm run dev` are running (PORT 5050 locally).
2. Open **Health & Governance** → **Run now** to verify fast-math cycles and `<100ms` badge.
3. To generate compliance narratives, add to local `.env`:

   ```bash
   OPENROUTER_API_KEY=sk-or-v1-...
   OPENROUTER_MODEL=openai/gpt-4o-mini
   ```

4. Restart the Node process, then click **Generate GDPR / NIST report**.
5. Poll the reports list until status is `completed`, then open the markdown body.

## What this deliberately does not do

- No LLM scoring of live pipeline batches
- No Istio / k8s requirement for the local resident agent
- No live production gateway taps — fixtures stand in until a real pipeline connector is added

## Files touched (summary)

- `server/analysis/fast-math.ts` (new)
- `server/governance/resident-agent.ts` (new)
- `server/governance/openrouter-client.ts` (new)
- `server/governance/async-compliance.ts` (new)
- `server/routes.ts`, `server/index.ts`
- `shared/schema.ts`
- `client/src/pages/health-governance.tsx`, `App.tsx`, `sidebar.tsx`
- `scripts/seed-synthetic.ts`, `fixtures/synthetic/*`
- `.env.example`, `docs/CONTINUOUS_HEALTH_GOVERNANCE.md`
- `package.json` / lockfile (`dotenv` dependency)
