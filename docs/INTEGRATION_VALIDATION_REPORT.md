# Frontend / Backend Integration Validation

Generated: 2026-10-13T06:22:00.000Z  
Base URL: http://127.0.0.1:5050

## Summary

| Total | Passed | Failed |
| --- | --- | --- |
| 21 | 21 | 0 |

**Verdict:** PASS

## Fixes applied during validation

- `queryClient` forwards `queryKey[1]` object fields as URL search params (AI Assets / Vulnerabilities / Monitoring filters).
- Dashboard Quick Actions and Alert Feed **View All** / trend **View Details** navigate or call APIs instead of no-ops.
- **Run Asset Scan** POSTs `/api/ai-scanner/scan` for `support-assistant` and routes to Vulnerabilities with a toast.
- System Monitoring UI now consumes the real `/api/monitoring/health` shape (`overall`, `components[]`, `summary`) instead of a mismatched nested mock schema.
- `/api/monitoring/health` returns **200** with overall status in the body (503 previously blanked the UI).
- Health checker: ESM `fs` import (disk + threat-config checks); optional `AGENT_ORCHESTRATOR_URL` only when set.
- Compliance **Export Report** downloads overview JSON; **Generate Compliance Report** → Health & Governance; **Schedule Assessment** opens the assessment dialog; **Policy Management** → Settings.
- Agentic **Create Agent** POSTs `/api/agentic/agents`; agentic auth uses real session + CISO/engineer roles.
- Integration harness logs in as **ciso.synthetic** via API session cookie (avoids RHF fill issues / SSO analyst role).

## Results

| ID | Name | Status |
| --- | --- | --- |
| API-NAV-DATA | Core page APIs return 200 with payloads | passed |
| API-ACTIONS | Primary mutating endpoints respond | passed |
| UI-LOGIN | Session lands on dashboard | passed |
| UI-NAV-* | All sidebar routes (11 pages) | passed |
| UI-BTN-PROMPT | Classify and store alerts | passed |
| UI-BTN-HEALTH-RUN | Run now | passed |
| UI-BTN-HEALTH-REPORT | Generate GDPR/NIST report | passed |
| UI-BTN-DASH-QUICK | Dashboard quick actions navigate / scan | passed |
| UI-BTN-SYS-REFRESH | System Monitoring Refresh | passed |
| UI-BTN-COMPLIANCE | Compliance export / report nav | passed |
| UI-BTN-AGENTIC | Create Agent | passed |

Screenshots: `tests/regression/artifacts/integration`

## Remaining intentional local-only UX

- Monitoring page **Pause/Play** only toggles client refetch intervals (no backend pause endpoint).
- Component-derived System Monitoring alerts (when `/api/monitoring/alerts` is empty) are display-only and do not call Acknowledge.
