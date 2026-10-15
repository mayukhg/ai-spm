#!/usr/bin/env python3
"""
Synthetic data generator for AI-SPM Mixpanel analytics.

Setup:
  pip install mixpanel faker python-dotenv requests

Run:
  python scripts/generate_mixpanel_synthetic_data.py

Requires in .env (either naming convention works):
  MIXPANEL_PROJECT_TOKEN  (or MIXPANEL_TOKEN)
  MIXPANEL_SERVICE_ACCOUNT_USER  (or MIXPANEL_SERVICE_ACCOUNT_USERNAME)
  MIXPANEL_SERVICE_ACCOUNT_PASS  (or MIXPANEL_SERVICE_ACCOUNT_SECRET)
  MIXPANEL_PROJECT_ID
"""

from __future__ import annotations

import os
import uuid
import random
import requests
from datetime import datetime, timedelta
from pathlib import Path

from faker import Faker
from dotenv import load_dotenv

# Load repo-root .env regardless of cwd
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

TOKEN = (
    os.environ.get("MIXPANEL_PROJECT_TOKEN")
    or os.environ.get("MIXPANEL_TOKEN")
    or ""
)
SA_USERNAME = (
    os.environ.get("MIXPANEL_SERVICE_ACCOUNT_USER")
    or os.environ.get("MIXPANEL_SERVICE_ACCOUNT_USERNAME")
    or ""
)
SA_SECRET = (
    os.environ.get("MIXPANEL_SERVICE_ACCOUNT_PASS")
    or os.environ.get("MIXPANEL_SERVICE_ACCOUNT_SECRET")
    or ""
)
PROJECT_ID = os.environ.get("MIXPANEL_PROJECT_ID") or ""

if not all([TOKEN, SA_USERNAME, SA_SECRET, PROJECT_ID]):
    missing = [
        name
        for name, val in [
            ("MIXPANEL_PROJECT_TOKEN/MIXPANEL_TOKEN", TOKEN),
            ("MIXPANEL_SERVICE_ACCOUNT_USER/USERNAME", SA_USERNAME),
            ("MIXPANEL_SERVICE_ACCOUNT_PASS/SECRET", SA_SECRET),
            ("MIXPANEL_PROJECT_ID", PROJECT_ID),
        ]
        if not val
    ]
    raise SystemExit(f"Missing Mixpanel credentials in .env: {', '.join(missing)}")

fake = Faker()
NOW = datetime.utcnow()
NINETY_DAYS_AGO = NOW - timedelta(days=90)


def rand_date(start: datetime, end: datetime) -> datetime:
    delta = end - start
    seconds = max(0, int(delta.total_seconds()))
    return start + timedelta(seconds=random.randint(0, seconds))


def import_events(events: list[dict]) -> tuple[int, int]:
    """Send a batch of events via the Mixpanel Import API (supports backdating)."""
    url = f"https://api.mixpanel.com/import?project_id={PROJECT_ID}&strict=1"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    auth = (SA_USERNAME, SA_SECRET)
    ok = 0
    failed = 0
    for i in range(0, len(events), 200):
        chunk = events[i : i + 200]
        resp = requests.post(url, json=chunk, headers=headers, auth=auth, timeout=60)
        if resp.status_code in (200, 201, 202):
            ok += len(chunk)
            print(f"  ✓ Imported batch {i // 200 + 1} ({len(chunk)} events)")
        else:
            failed += len(chunk)
            print(f"  ⚠️  Import error ({resp.status_code}): {resp.text[:300]}")
    return ok, failed


def set_user_profile(distinct_id: str, traits: dict) -> None:
    """Set a user profile via Mixpanel Engage API."""
    url = "https://api.mixpanel.com/engage#profile-set"
    payload = [
        {
            "$token": TOKEN,
            "$distinct_id": distinct_id,
            "$set": traits,
        }
    ]
    requests.post(url, json=payload, timeout=30)


def make_event(distinct_id: str, event_name: str, props: dict, ts: datetime) -> dict:
    return {
        "event": event_name,
        "properties": {
            "distinct_id": distinct_id,
            "token": TOKEN,
            "time": int(ts.timestamp()),
            "$insert_id": str(uuid.uuid4()),
            **props,
        },
    }


PLANS = ["free"] * 6 + ["pro"] * 3 + ["enterprise"] * 1
ROLES = ["admin", "analyst", "viewer"]
AUTH_METHODS = ["email", "google", "sso"]
FRAMEWORKS = ["openai", "huggingface", "aws_sagemaker", "azure_ml", "custom"]
ASSET_TYPES = ["model", "dataset", "pipeline", "api_endpoint"]
INTEGRATIONS = ["github", "aws", "azure", "gcp", "jira", "slack", "okta", "snowflake"]
VIOLATION_TYPES = [
    "data_leakage",
    "pii_exposure",
    "model_drift",
    "unauthorized_access",
    "prompt_injection",
]
ALERT_TYPES = [
    "anomaly_detected",
    "policy_breach",
    "access_violation",
    "data_exposure",
    "model_degradation",
]
REPORT_TYPES = ["sox", "gdpr", "hipaa", "iso27001", "custom"]
SEVERITIES = ["critical", "high", "medium", "low"]
RISK_LEVELS = ["critical", "high", "medium", "low"]
SECTIONS = ["overview", "assets", "risks", "policies", "alerts", "reports", "settings"]


def generate_user_journey(user_index: int) -> list[dict]:
    distinct_id = str(uuid.uuid4())
    plan = random.choice(PLANS)
    role = random.choice(ROLES)
    auth_method = random.choice(AUTH_METHODS)
    org = fake.company()
    is_churned = user_index < 10

    signup_date = rand_date(NINETY_DAYS_AGO, NOW - timedelta(days=32 if is_churned else 5))
    activity_end = (
        signup_date + timedelta(days=random.randint(10, 30)) if is_churned else NOW
    )

    events: list[dict] = []

    set_user_profile(
        distinct_id,
        {
            "$email": fake.email(),
            "$name": fake.name(),
            "plan": plan,
            "role": role,
            "org_name": org,
            "$created": signup_date.isoformat(),
            "is_churned": is_churned,
        },
    )

    events.append(
        make_event(
            distinct_id,
            "user_signed_up",
            {"method": auth_method, "plan": plan, "org_name": org},
            signup_date,
        )
    )
    events.append(
        make_event(
            distinct_id,
            "user_logged_in",
            {"method": auth_method},
            signup_date + timedelta(minutes=1),
        )
    )

    onboarding_steps = [
        "profile_setup",
        "first_integration",
        "first_scan",
        "invite_team",
        "complete",
    ]
    steps_completed = random.randint(2, 5)
    step_time = signup_date + timedelta(minutes=5)
    for i, step_name in enumerate(onboarding_steps[:steps_completed]):
        events.append(
            make_event(
                distinct_id,
                "onboarding_step_completed",
                {"step": i + 1, "step_name": step_name},
                step_time,
            )
        )
        step_time += timedelta(minutes=random.randint(2, 15))
    if steps_completed == 5:
        events.append(
            make_event(
                distinct_id,
                "onboarding_completed",
                {
                    "time_to_complete_seconds": int(
                        (step_time - signup_date).total_seconds()
                    ),
                    "integrations_connected": random.randint(1, 3),
                },
                step_time,
            )
        )

    num_integrations = random.randint(1, 3)
    chosen_integrations = random.sample(INTEGRATIONS, num_integrations)
    for intg in chosen_integrations:
        t = rand_date(signup_date + timedelta(hours=1), activity_end)
        events.append(
            make_event(
                distinct_id,
                "integration_connected",
                {
                    "integration_name": intg,
                    "connection_method": random.choice(
                        ["oauth", "api_key", "service_account"]
                    ),
                },
                t,
            )
        )

    num_assets = random.randint(2, 10)
    asset_ids = [str(uuid.uuid4()) for _ in range(num_assets)]
    asset_types = [random.choice(ASSET_TYPES) for _ in asset_ids]
    asset_risk_levels = [random.choice(RISK_LEVELS) for _ in asset_ids]
    asset_reg_time = signup_date + timedelta(hours=2)

    for idx, asset_id in enumerate(asset_ids):
        asset_type = asset_types[idx]
        risk_level = asset_risk_levels[idx]

        events.append(
            make_event(
                distinct_id,
                "ai_asset_registered",
                {
                    "asset_type": asset_type,
                    "source": random.choice(["manual", "auto_scan", "import"]),
                    "framework": random.choice(FRAMEWORKS),
                    "risk_level": risk_level,
                },
                asset_reg_time,
            )
        )
        asset_reg_time += timedelta(hours=random.randint(1, 48))

        for _ in range(random.randint(2, 6)):
            t = rand_date(asset_reg_time, activity_end)
            events.append(
                make_event(
                    distinct_id,
                    "ai_asset_viewed",
                    {
                        "asset_id": asset_id,
                        "asset_type": asset_type,
                        "risk_level": risk_level,
                    },
                    t,
                )
            )

        for _ in range(random.randint(1, 3)):
            start_t = rand_date(asset_reg_time, activity_end)
            duration = random.randint(10, 300)
            risk_score = random.randint(0, 100)
            prev_risk = random.choice(RISK_LEVELS)
            events.append(
                make_event(
                    distinct_id,
                    "risk_assessment_started",
                    {
                        "asset_id": asset_id,
                        "asset_type": asset_type,
                        "triggered_by": random.choice(["manual", "scheduled", "auto"]),
                    },
                    start_t,
                )
            )
            events.append(
                make_event(
                    distinct_id,
                    "risk_assessment_completed",
                    {
                        "asset_id": asset_id,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "findings_count": random.randint(0, 15),
                        "duration_seconds": duration,
                        "previous_risk_level": prev_risk,
                    },
                    start_t + timedelta(seconds=duration),
                )
            )

        if random.random() < 0.3:
            t = rand_date(asset_reg_time, activity_end)
            violation_type = random.choice(VIOLATION_TYPES)
            severity = random.choice(SEVERITIES)
            events.append(
                make_event(
                    distinct_id,
                    "policy_violation_detected",
                    {
                        "violation_type": violation_type,
                        "severity": severity,
                        "asset_id": asset_id,
                        "policy_name": f"{violation_type}_policy",
                        "auto_remediated": random.random() < 0.4,
                    },
                    t,
                )
            )

        if random.random() < 0.4:
            t = rand_date(asset_reg_time, activity_end)
            alert_id = str(uuid.uuid4())
            severity = random.choice(SEVERITIES)
            events.append(
                make_event(
                    distinct_id,
                    "alert_triggered",
                    {
                        "alert_type": random.choice(ALERT_TYPES),
                        "severity": severity,
                        "asset_id": asset_id,
                        "auto_assigned": random.random() < 0.5,
                    },
                    t,
                )
            )
            if random.random() < 0.7:
                resolve_minutes = random.randint(5, 1440)
                events.append(
                    make_event(
                        distinct_id,
                        "alert_resolved",
                        {
                            "alert_id": alert_id,
                            "resolution_type": random.choice(
                                ["manual", "auto_remediated", "dismissed"]
                            ),
                            "time_to_resolve_minutes": resolve_minutes,
                            "severity": severity,
                        },
                        t + timedelta(minutes=resolve_minutes),
                    )
                )
            else:
                events.append(
                    make_event(
                        distinct_id,
                        "alert_dismissed",
                        {
                            "alert_id": alert_id,
                            "reason": random.choice(
                                ["false_positive", "known_issue", "out_of_scope"]
                            ),
                        },
                        t + timedelta(minutes=random.randint(1, 60)),
                    )
                )

    for _ in range(random.randint(0, 3)):
        t = rand_date(signup_date + timedelta(days=1), activity_end)
        events.append(
            make_event(
                distinct_id,
                "policy_created",
                {
                    "policy_type": random.choice(VIOLATION_TYPES),
                    "scope": random.choice(["global", "team", "asset"]),
                },
                t,
            )
        )

    if plan in ["pro", "enterprise"]:
        for _ in range(random.randint(1, 4)):
            t = rand_date(signup_date + timedelta(days=7), activity_end)
            events.append(
                make_event(
                    distinct_id,
                    "compliance_report_exported",
                    {
                        "report_type": random.choice(REPORT_TYPES),
                        "format": random.choice(["pdf", "csv", "json"]),
                        "asset_count": random.randint(1, num_assets),
                    },
                    t,
                )
            )

    if role == "admin":
        for _ in range(random.randint(0, 4)):
            t = rand_date(signup_date + timedelta(days=1), activity_end)
            events.append(
                make_event(
                    distinct_id,
                    "team_member_invited",
                    {
                        "role": random.choice(ROLES),
                        "invitation_method": random.choice(["email", "link"]),
                    },
                    t,
                )
            )

    active_days = int((activity_end - signup_date).days)
    num_views = random.randint(5, max(5, active_days * 2)) if active_days > 0 else 5
    for _ in range(num_views):
        t = rand_date(signup_date + timedelta(hours=3), activity_end)
        events.append(
            make_event(
                distinct_id,
                "dashboard_viewed",
                {"section": random.choice(SECTIONS)},
                t,
            )
        )

    for _ in range(random.randint(0, 10)):
        t = rand_date(signup_date + timedelta(hours=3), activity_end)
        events.append(
            make_event(
                distinct_id,
                "search_performed",
                {
                    "query_length": random.randint(3, 50),
                    "result_count": random.randint(0, 30),
                    "section": random.choice(SECTIONS),
                },
                t,
            )
        )

    return events


def main() -> None:
    print("🚀 Starting AI-SPM synthetic data generation...\n")
    print(f"   Token (last 4): ...{TOKEN[-4:]}")
    print(f"   Project ID: {PROJECT_ID}")
    print(f"   Date range: {NINETY_DAYS_AGO.date()} → {NOW.date()}\n")

    all_events: list[dict] = []
    for i in range(50):
        user_events = generate_user_journey(i)
        all_events.extend(user_events)
        label = "churned" if i < 10 else "active"
        print(f"   👤 User {i + 1:02d}/50 ({label}): {len(user_events)} events")

    print(f"\n📤 Importing {len(all_events)} events to Mixpanel...")
    ok, failed = import_events(all_events)

    print(
        f"""
✅ Synthetic data generation complete!
   Users created:  50 (10 churned, 40 active)
   Events sent:    {len(all_events)} (ok={ok}, failed={failed})
   Date range:     {NINETY_DAYS_AGO.date()} → {NOW.date()}
   Token:          ...{TOKEN[-4:]}

Next steps:
  1. Go to https://mixpanel.com → Events to confirm data is flowing
  2. Check User Profiles to see the 50 synthetic users
  3. Build your first report or ask Mixpanel Agent to create a dashboard!
"""
    )


if __name__ == "__main__":
    main()
