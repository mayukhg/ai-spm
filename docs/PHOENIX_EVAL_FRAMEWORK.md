# AI-SPM LLM Eval Framework (Arize Phoenix)

Product-oriented documentation for how we host, instrument, and evaluate the **async governance LLM** path — the only place this product deliberately calls a large language model.

Companion technical tracing notes: [`PHOENIX_OBSERVABILITY.md`](./PHOENIX_OBSERVABILITY.md).

---

## 1. Why this eval framework exists (PM framing)

### Customer problem we are guarding against

Silent data decay and compliance risk (see product narrative: deployment illusion → drift → silent failure → regulatory exposure). The governance LLM turns **statistical monitoring evidence** into **audit-ready GDPR / NIST narratives**. If that narrative is wrong, incomplete, or invented, the product creates a *worse* failure mode than no report at all: **false assurance**.

### Product decision: evaluate the LLM path, not the Fast Math path

| Path | Eval approach | PM rationale |
| --- | --- | --- |
| Practical Fast Math (resident agent, &lt;100ms) | Unit / regression / cycle budgets | Deterministic; latency is the success metric |
| Async OpenRouter governance reports | Phoenix traces + structured eval dataset | Non-deterministic; trust, grounding, and audit structure are the success metrics |

This separation is intentional: we do **not** put LLM latency on the critical monitoring loop, and we do **not** treat LLM quality as a substitute for statistical health scores.

### Personas the eval set optimizes for

| Persona | What “good” looks like in an eval case |
| --- | --- |
| **CISO** | Clear severity, silent-failure language when warranted, actionable remediation |
| **Compliance officer** | Named frameworks (GDPR / NIST), Gaps + Remediation sections, no fabricated controls |
| **Analyst / engineer** | Evidence (quality, KS drift, IF/LOF) reflected accurately in the narrative |

---

## 2. How the framework is hosted

### Components

```
┌─────────────────────┐     OTLP/HTTP      ┌──────────────────────────┐
│ AI-SPM Node app     │ ─────────────────► │ Arize Phoenix            │
│ :5050               │   /v1/traces       │ Collector + UI :6006     │
│                     │                    │ Project: my-cursor-app   │
│ • tracer bootstrap  │                    └──────────────────────────┘
│ • OpenAI SDK        │
│   → OpenRouter      │
│ • withSpan(CHAIN)   │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Seed / eval runner  │  npm run phoenix:seed
│ fixtures/synthetic/ │  → eval-runs.json + spans
│ phoenix/            │
└─────────────────────┘
```

### Hosting modes

| Mode | How | When to use |
| --- | --- | --- |
| **Local Docker (default)** | `docker run -p 6006:6006 arizephoenix/phoenix:latest` | Dev, demos, interview walkthroughs |
| **App-coupled tracing** | Node process exports spans on every governance report | Continuous observability in local/staging |
| **Offline / CI seed** | `npm run phoenix:seed` without live key uses synthetic outputs | Populate Phoenix for demos when OpenRouter is unavailable |
| **Phoenix Cloud (optional)** | Set `PHOENIX_COLLECTOR_ENDPOINT` + `PHOENIX_API_KEY` / `PHOENIX_CLIENT_HEADERS` | Shared team projects |

### Environment (host binding)

Configured via `.env` / `.env.example`:

| Variable | Role | Default / example |
| --- | --- | --- |
| `PHOENIX_COLLECTOR_ENDPOINT` | Base URL of Phoenix (OTLP normalized to `/v1/traces`) | `http://localhost:6006` |
| `PHOENIX_PROJECT_NAME` | Project bucket in the Phoenix UI | `my-cursor-app` |
| `PHOENIX_CLIENT_HEADERS` | Optional auth headers (`api_key=...`) | blank for local |
| `PHOENIX_API_KEY` | Optional Bearer auth for Phoenix Cloud | unset locally |
| `PHOENIX_TRACING_ENABLED` | Kill switch | unset = enabled |
| `OPENROUTER_API_KEY` | Live LLM for app + live seed mode | required for live spans |
| `OPENROUTER_MODEL` | Model under eval | `openai/gpt-4o-mini` |

### Runtime surfaces that emit traces

1. **In-app:** `POST /api/governance/reports` → `synthesizeReport` (CHAIN) → OpenRouter chat (LLM).
2. **Seed job:** `npm run phoenix:seed` walks `ai-spm-governance-eval` examples and emits CHAIN + LLM spans per case.

UI: open **http://localhost:6006** → project **`my-cursor-app`**.

---

## 3. Eval dataset & parameters

Dataset file: [`fixtures/synthetic/phoenix/eval-dataset.json`](../fixtures/synthetic/phoenix/eval-dataset.json)  
Dataset name: **`ai-spm-governance-eval`** (v1.0.0)

### 3.1 Case inventory (why each case exists)

| Case ID | Asset posture | Frameworks | Severity | PM intent |
| --- | --- | --- | --- | --- |
| `gov-eval-001` | Mostly healthy; freshness warn; mild KS/IF | GDPR + NIST | medium | Happy-path audit pack still calls out the weak dimension |
| `gov-eval-002` | Completeness/freshness fail; drifted; high LOF | GDPR | high | CISO path: must surface failure, not soft-pedal |
| `gov-eval-003` | All six quality dims strong; no drift/anomalies | NIST | low | Healthy baseline; avoid inventing problems |
| `gov-eval-004` | Warn quality; watch drift; medium IF | GDPR + NIST | medium | “Watch” state before silent failure — Manage early |
| `gov-eval-005` | Multi-dim fail; severe drift; critical IF/LOF | GDPR + NIST | critical | Maps to **silent data decay** slide; urgent remediation |

Cases are stratified by **severity** and **persona** metadata so PMs can slice eval results the same way stakeholders slice risk.

### 3.2 Input parameters (what we feed the model)

| Parameter | Source in fixture | Why selected (PM) |
| --- | --- | --- |
| `assetName` | Synthetic inventory names used in the product | Grounds narrative in real product objects CISOs recognize |
| `frameworks[]` | `GDPR`, `NIST AI RMF`, or both | Matches buyer compliance jobs; dual-framework cases stress coverage |
| `evidence.quality[]` | Six dimensions: completeness, accuracy, consistency, validity, uniqueness, freshness | Aligns LLM story with **realtime product truth** (Fast Math), not generic prose |
| `evidence.quality[].metricValue` / `status` | pass / warn / fail | Forces severity-accurate language |
| `evidence.drift[]` | KS score + status (`stable` / `watch` / `drifted`) | Encodes the decay curve narrative in measurable form |
| `evidence.anomalies[]` | Isolation Forest / LOF + severity + affected records | Ties “silent failure” to concrete detection methods marketed in Health & Governance |
| System prompt instructions | Fixed compliance-agent prompt in seed + app | Constrains voice to **audit-ready**; forbids inventing controls |

### 3.3 Reference / success parameters (how we score)

Defined per case under `reference_output` and global `evaluators`:

| Parameter | Type | Why selected (PM) |
| --- | --- | --- |
| `must_include[]` | Deterministic contains-all | Cheap gate for **document structure** auditors expect (Executive Summary, Gaps, Remediation, framework names) |
| `must_not_invent_controls` | LLM-as-judge rubric | Primary trust metric: no false assurance |
| `must_call_out_failures` | LLM-as-judge / policy flag | High/critical cases must not read as “all clear” |
| `tone` | `audit-ready` / `urgent-audit` | Matches persona communication (compliance vs CISO crisis) |
| `expected_posture` | e.g. `healthy` | Prevents over-alarming on clean evidence (noise → alert fatigue) |
| `structure_sections` evaluator | Code check in `phoenix:seed` | CI/demo-friendly binary score without waiting on a judge model |
| `no_fabricated_controls` evaluator | LLM-as-judge | Product risk = regulatory liability |
| `evidence_grounding` evaluator | LLM-as-judge | Narrative must track quality/drift/anomaly numbers |

### 3.4 Observability parameters captured in Phoenix spans

| Span / attribute | Meaning | PM use |
| --- | --- | --- |
| CHAIN `governance.synthesize_report` / `governance.eval_case` | Workflow unit | Latency of “report generation job” |
| LLM OpenInference span (OpenAI instrumentor) | Model call | Token cost, prompt/completion, errors |
| `llm.model_name` | Usually `openai/gpt-4o-mini` | Cost/quality tradeoff tracking |
| `eval.example_id` / `eval.dataset` | Case linkage | Slice traces by fixture |
| `eval.meta.persona` / `severity` | Stakeholder slice | Prioritize failing critical/CISO cases first |
| Token counts + latency | Usage | Budget async path; never confuse with Fast Math SLA |

### 3.5 Seed run artifact

[`fixtures/synthetic/phoenix/eval-runs.json`](../fixtures/synthetic/phoenix/eval-runs.json) records per-case:

- `mode`: `live` vs `synthetic`
- `latency_ms`, `usage` (prompt/completion/total tokens)
- `structure_sections_pass` + `missing_sections`
- `output_preview`

This is the lightweight “scorecard” PMs can open without logging into Phoenix, while Phoenix remains the system of record for full traces.

---

## 4. How to run (operator checklist)

```bash
# 1) Host Phoenix locally
docker run -d --name ai-spm-phoenix -p 6006:6006 arizephoenix/phoenix:latest

# 2) Ensure .env has Phoenix + OpenRouter (for live mode)
# PHOENIX_COLLECTOR_ENDPOINT=http://localhost:6006
# PHOENIX_PROJECT_NAME=my-cursor-app

# 3) Start AI-SPM (tracing boots on import)
npm run dev

# 4) Populate eval traces + scorecard
npm run phoenix:seed

# 5) Optional: generate a report from the UI/API (in-app CHAIN+LLM spans)
# Health & Governance → Generate GDPR / NIST report
```

---

## 5. Product principles encoded in the framework

1. **Evidence in, narrative out** — eval inputs are product telemetry shapes, not free-form chat.
2. **No false assurance** — inventing controls fails the most important evaluator.
3. **Severity stratification** — critical silent-decay cases are first-class, not edge cases.
4. **Persona-aware success** — CISO vs compliance “good” differ; metadata makes that explicit.
5. **Cost/latency honesty** — LLM evals live on the async path; Fast Math keeps the &lt;100ms promise.
6. **Demoable hosting** — local Phoenix on `:6006` so stakeholders can see traces in an interview or design review without cloud setup.

---

## 6. File map

| Path | Role |
| --- | --- |
| `server/observability/tracer.ts` | Phoenix OTEL register + OpenAI instrumentor |
| `server/governance/openrouter-client.ts` | Instrumentable LLM client |
| `server/governance/async-compliance.ts` | CHAIN-wrapped report synthesis |
| `fixtures/synthetic/phoenix/eval-dataset.json` | Cases + evaluator rubrics |
| `fixtures/synthetic/phoenix/synthetic-outputs.json` | Offline reference narratives |
| `fixtures/synthetic/phoenix/eval-runs.json` | Latest seed scorecard |
| `scripts/seed-phoenix-eval.ts` | Host population + structure scoring |
| `docs/PHOENIX_OBSERVABILITY.md` | Tracing implementation detail |
