
# Base Password Strength Model

**Single file** wrapper around `zxcvbn` exposing only what most UIs need:

- `score` (0–4)
- `crack_time_display` (human-friendly string)
- `suggestions` (list of short tips)
- `warning` (optional single-line warning)

## Install

```bash
pip install zxcvbn
```

## Files

- `password_strength.py` — the base model (single file)
- `run_tests.py` — optional tiny driver

## Quick Start

```bash
python run_tests.py
```

Or import:

```python
from password_strength import assess_password
print(assess_password("CorrectHorseBatteryStaple"))
```
