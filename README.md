# ThreatKit

A teaching/learning security toolkit that helps users evaluate **Passwords**, **URLs**, **Emails (Phishing)**, and **Files (Malware)** with explainable results.  
Frontend is Flask/Jinja + Bootstrap 5 (dark theme). Results are shown with consistent score meters and human-readable labels.

> **Privacy & Disclaimer:** Inputs are processed in memory and not intentionally persisted. No system is perfect—low risk ≠ safe. Use antivirus and follow org policies.

---

## Features

- **Password Checker** — strength via `zxcvbn` (**0–4** score + label, reasons, suggestions)
- **URL Checker** — heuristic checks (protocol, TLD, symbols, length) → normalized score (0–4)
- **Email/Phishing** — rules + optional HF model; **0–100** risk with labels (Very Low → Critical)
- **Malware (planned)** — static file checks (hash/MIME), no execution
- **Explainability** — reason chips + **Summary / Details / JSON** tabs
- **UI Consistency** — circular score meter component (supports 0–4 and 0–100)
- **Privacy Modal** — first-visit popup requiring acceptance (stored in `localStorage`)

---

## Quick Start

### 1) Requirements
- Python 3.10+ recommended
- (Optional for Email ML): `transformers`, `torch`

### 2) Setup
```bash
# clone and enter
git clone <your-repo-url>
cd ThreatKit

# create and activate venv
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

# install deps
pip install -r requirements.txt
# if you want email ML model:
pip install transformers torch
