# threatkit/password/strength.py
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import json

try:
    from zxcvbn import zxcvbn  # Python port
except Exception as e:
    raise ImportError("zxcvbn is required. Install with: pip install zxcvbn") from e


def assess_password(password: str, user_inputs: Optional[List[str]] = None) -> Dict:
    """
    Return a tiny dict: score (0-5), crack_time_display, suggestions, warning.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    r = zxcvbn(password, user_inputs=user_inputs or [])

    # Prefer conservative offline-slow display; fall back to others if missing
    d = r.get("crack_times_display", {}) or {}
    display = (
        d.get("offline_slow_hashing_1e4_per_second")
        or d.get("offline_fast_hashing_1e10_per_second")
        or d.get("online_no_throttling_10_per_second")
        or "unknown"
    )

    fb = r.get("feedback", {}) or {}

    raw_score = int(r.get("score", 0))
    score_0_to_5 = round(raw_score * (5/4))

    return {
        "score": score_0_to_5, 
        "crack_time_display": display,
        "suggestions": fb.get("suggestions") or [],
        "warning": fb.get("warning") or None,
    }



# ---------- Logging (timestamp + results only; no password) ----------

_RESULTS_PATH = Path(__file__).resolve().parent / "tests" / "password_test_results.md"

def save_result(result: Dict) -> Path:
    """
    Append a JSON object (one line) with timestamp + result fields to tests/password_test_results.md.
    No password or mask is stored.
    """
    _RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": result.get("score"),
        "crack_time_display": result.get("crack_time_display"),
        "warning": result.get("warning"),
        "suggestions": result.get("suggestions", []),
    }

    with _RESULTS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")  # JSONL

    return _RESULTS_PATH


if __name__ == "__main__":
    try:
        pw = input("Enter a password to assess: ").strip()
        res = assess_password(pw)
        print(res)
        path = save_result(res)
        print(f"Result saved to: {path}")
    except Exception as exc:
        print(f"Error: {exc}")
