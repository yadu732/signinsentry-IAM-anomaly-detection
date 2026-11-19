# 🔐 SignInSentry | IAM Login Anomaly Detection & Investigation

A portfolio-ready **Identity and Access Management + Data Science** project. It creates synthetic user profiles and sign-in events, extracts behavioral signals, applies transparent risk rules and an Isolation Forest model, then builds a Streamlit investigation dashboard.

> **Safety:** This is a synthetic lab, not a live account monitoring system or a production security tool. Scoring is review prioritization, not evidence of account compromise. No real passwords, user credentials, emails, or enterprise logs are used.

## Features

- Identity profiles containing a home country, trusted device, typical working hours, and privilege level.
- UTC sign-in event simulation with **three distinct injected attack patterns**, occasional benign travel, and synthetic ground-truth labels for testing only.
- Explainable rules: unusual country, unknown device, off-hours sign-in, failed login, 3+ failures per 15 minutes, privileged login without MFA.
- Isolation Forest trained on numeric **observable sign-in features only**, with optional contamination control (default 5%).
- A hybrid alert: rule points + small model anomaly bonus. Users can inspect exact triggering rules.
- Evaluation report with precision, recall, F1, and confusion matrix **on injected patterns only**.
- Reproducible command-line demo, tests, GitHub Actions, and Dockerfile.

### Architecture

```text
Synthetic identity profiles ──┐
                              ├─> temporal features ─┬─> explainable risk rules ──┐
Synthetic sign-in telemetry ──┘                       └─> Isolation Forest ────────┤
                                                                                └─> alert queue ─> Streamlit
Injected simulated labels ─────────────────────────────────────> offline evaluation only
```

**Critical distinction:** `simulated_attack` is used only for offline scoring evaluation and is never a feature or fitting target.

## Run locally (Windows PowerShell)

```powershell
cd signinsentry
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m signinsentry.cli generate --out data
python -m signinsentry.cli score --data data --out reports
pytest -q
streamlit run app.py
```

Visit **http://localhost:8501**. Data files are already included, so regeneration is optional. On macOS/Linux, activate using `source .venv/bin/activate`.

### Docker

```bash
docker build -t signinsentry .
docker run --rm -p 8501:8501 signinsentry
```

## Folder layout

```text
src/signinsentry/generate.py       Identity and sign-in log generator
src/signinsentry/detect.py         15-minute rolling features, risk rules, anomaly model, synthetic evaluation
src/signinsentry/cli.py            Reproducible CLI
app.py                              Streamlit alert queue and investigation panels
data/                               Fictional telemetry and profiles
reports/                            Generated scores and synthetic metrics
tests/                              Unit and security logic regression tests
.github/workflows/ci.yml           CI
```

## Threat-simulation assumptions and limitations

- IP addresses are documentation-only ranges (`192.0.2.0/24`, `203.0.113.0/24`); countries are also simulated.
- The patterns are intentionally conspicuous. A high offline recall on these synthetic attacks **does not indicate strong real-world detection**. False positives and behavior drift are likely in actual environments.
- Working hours are interpreted as **UTC for the demo**, not the user's local time zone. A real system must use local time zones, job schedules and traveling employees.
- The generator stores one nominal trusted device per user. Real device trust requires registry, attestation and device lifecycle policies.
- In production, train and tune on a historical clean baseline, compare with rule-only alerts, use holdout time splits, monitor drift and audit the privacy implications.
- This uses no Microsoft Graph or Entra ID API because no tenant or paid license is required to demonstrate the method. Live connector access would require explicit authorized scopes and privacy controls.

