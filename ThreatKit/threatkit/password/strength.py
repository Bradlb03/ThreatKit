from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import json

try:
    from zxcvbn import zxcvbn  # Python port
except Exception as e:
    raise ImportError("zxcvbn is required. Install with: pip install zxcvbn") from e


def assess_password(password: str, user_inputs: Optional[List[str]] = None) -> Dict:
    #Return a tiny dict: score (0-4), crack_time_display, suggestions, warning.
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
    return {
        "score": int(r.get("score", 0)),              
        "crack_time_display": display,                  
        "suggestions": fb.get("suggestions") or [],    
        "warning": fb.get("warning") or None,          
    }


def _mask_password(password: str) -> str:
    #Mask the password so only a partial portion is visible in logs.
    if len(password) <= 2:
        return "*" * len(password)
    if len(password) <= 6:
        return password[0] + "*" * (len(password) - 2) + password[-1]
    return password[:2] + "*" * max(4, len(password) - 4) + password[-2:]


def _save_result(password: str, result: Dict) -> None:
    #Save results in JSON dictionary format to password/tests/password_test_results.md
    out_path = Path("password/tests/password_test_results.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    masked = _mask_password(password)
    record = {
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
        "password_masked": masked,
        "score": result.get("score"),
        "crack_time_display": result.get("crack_time_display"),
        "suggestions": result.get("suggestions", []),
        "warning": result.get("warning"),
    }

    # Append JSON object per line for readability
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, indent=4) + "\n")

    print(f"Result saved to: {out_path}")


if __name__ == "__main__":
    try:
        pw = input("Enter a password to assess: ").strip()
        result = assess_password(pw)
        print(result)
        _save_result(pw, result)
    except Exception as exc:
        print(f"Error: {exc}")
