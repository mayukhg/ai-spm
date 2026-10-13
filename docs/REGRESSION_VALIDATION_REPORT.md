# Regression Validation Report

Generated: 2026-10-13T07:36:18.930Z
Base URL: http://127.0.0.1:5050
Window: 2026-10-13T07:35:22.519Z → 2026-10-13T07:36:18.930Z

## Summary

| Total | Passed | Failed | Skipped |
| --- | --- | --- | --- |
| 29 | 29 | 0 | 0 |

**Verdict:** PASS

## Coverage map (changes under test)

| Change area | Suite cases |
| --- | --- |
| Practical Fast Math (quality, KS, Isolation Forest, LOF) | UNIT-* |
| Resident agent health APIs + Run now | FUNC-HEALTH-* |
| Async OpenRouter governance reports | FUNC-GOV-* |
| Prompt / jailbreak / token classifier | FUNC-LLM-* |
| Dashboard metrics / auth / theme / pages | FUNC-CORE-*, UI-* |
| Health & Governance UI + Prompt Checks UI | UI-* |

## UNIT results

| ID | Name | Status | ms | Notes |
| --- | --- | --- | --- | --- |
| UNIT-QM-01 | Six quality dimensions score clean current extract near 1.0 | passed | 0 |  |
| UNIT-QM-02 | Dirty extract fails completeness/uniqueness/validity | passed | 0 |  |
| UNIT-KS-01 | KS drift detects baseline vs current amount shift | passed | 1 |  |
| UNIT-IF-01 | Isolation Forest flags planted high-amount outliers | passed | 53 |  |
| UNIT-LOF-01 | Local Outlier Factor flags planted outliers | passed | 2 |  |
| UNIT-FM-01 | Full fast-math monitor stays under 100ms budget | passed | 51 |  |
| UNIT-FM-02 | Realtime path module does not import OpenRouter | passed | 0 |  |

## FUNCTIONAL results

| ID | Name | Status | ms | Notes |
| --- | --- | --- | --- | --- |
| FUNC-CORE-01 | Health endpoint returns ok | passed | 3 |  |
| FUNC-CORE-02 | Login accepts synthetic CISO credentials | passed | 49 |  |
| FUNC-CORE-03 | Dashboard metrics include synthetic posture fields | passed | 12 |  |
| FUNC-CORE-04 | Dashboard trend returns stored snapshots | passed | 5 |  |
| FUNC-LLM-01 | Local prompt classifier matches fixture labels | passed | 1 |  |
| FUNC-LLM-02 | GET /api/llm/classifications returns three scored prompts | passed | 4 |  |
| FUNC-LLM-03 | POST /api/llm/classifications stores block alerts | passed | 13 |  |
| FUNC-HEALTH-01 | Resident agent status exposes fast-math methods and no realtime LLM | passed | 2 |  |
| FUNC-HEALTH-02 | Run now completes under 100ms and persists a cycle | passed | 100 |  |
| FUNC-GOV-01 | OpenRouter configuration is reported from env | passed | 2 |  |
| FUNC-GOV-02 | POST /api/governance/reports queues async GDPR/NIST synthesis | passed | 12167 |  |
| FUNC-CORE-05 | Settings status exposes syntheticFixtures | passed | 6 |  |

## UI results

| ID | Name | Status | ms | Notes |
| --- | --- | --- | --- | --- |
| UI-BOOT-01 | Headless Chromium launches | passed | 2082 |  |
| UI-AUTH-01 | Auth page renders black theme and sign-in controls | passed | 2743 |  |
| UI-AUTH-02 | Synthetic login reaches dashboard | passed | 31729 |  |
| UI-DASH-01 | Dashboard shows metrics and threat alerts | passed | 2 |  |
| UI-NAV-01 | Sidebar includes Prompt Checks and Health & Governance | passed | 0 |  |
| UI-PROMPT-01 | Prompt Checks page shows three classifications | passed | 616 |  |
| UI-HEALTH-01 | Health & Governance shows resident agent and OpenRouter status | passed | 632 |  |
| UI-HEALTH-02 | Run now creates a monitoring cycle row | passed | 52 |  |
| UI-HEALTH-03 | Generate report queues and lists a governance report | passed | 66 |  |
| UI-THEME-01 | Primary pages keep black background | passed | 3752 |  |

## Environment notes

- Functional and UI suites target the running app (default `http://127.0.0.1:5050`).
- OpenRouter live completion is asserted when `OPENROUTER_API_KEY` is set; otherwise queued-status checks may be skipped.
- UI suite uses Puppeteer headless Chromium.
