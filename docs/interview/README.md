# AI-SPM Product Management Interview Demo

## Deliverable

| File | Use |
| --- | --- |
| [AI_SPM_PM_Demo.mp4](./AI_SPM_PM_Demo.mp4) | Silent ~3.2 min live walkthrough. Hybrid PM captions **burned into every frame**. No audio. No separate SRT. |
| [PM_DEMO_PLAYER.html](./PM_DEMO_PLAYER.html) | Browser player + interview tips. |

## What’s in the walkthrough

Live click-through of the running app (CISO session):

1. Auth as CISO  
2. Dashboard (outcome home)  
3. Run Asset Scan → Vulnerabilities  
4. Prompt Checks → Classify and store alerts  
5. Health & Governance → Run now → Generate GDPR/NIST report  
6. Compliance → Export Report  
7. Agentic Workflows → Create Agent  
8. System Monitoring → Refresh  
9. Threat Configuration (CISO-gated)  
10. Back to Dashboard (spine close)

## Rebuild

```bash
# App must be running on :5050 with synthetic fixtures
node docs/interview/build-silent-walkthrough.mjs
```

## Interview tip

Share the MP4 (captions are burned in). Pause on Health & Governance to talk the Fast Math vs async OpenRouter tradeoff.
