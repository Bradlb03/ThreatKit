# requires: pip install zxcvbn
from pathlib import Path
from datetime import datetime
import json

# Import base model
from strength import assess_password 

SAMPLES = [
    "123456",
    "password",
    "hello123",
    "Summer2024!",
    "CorrectHorseBatteryStaple",
    "Tr0ub4dor&3",
    "R@nd0mLongPassphraseWithSymbolsAndNumbers2025",
]

def mask(p: str) -> str:
    if len(p) <= 2:
        return "*" * len(p)
    if len(p) <= 6:
        return p[0] + "*" * (len(p) - 2) + p[-1]
    return p[:2] + "*" * max(4, len(p) - 4) + p[-2:]

def write_json_record(out_path: Path, password: str, result: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
        "password_masked": mask(password),
        "score": result.get("score"),
        "crack_time_display": result.get("crack_time_display"),
        "suggestions": result.get("suggestions", []),
        "warning": result.get("warning"),
    }
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, indent=4) + "\n")

def main():
    out_file = Path("password/tests/password_test_results.md")
    for pw in SAMPLES:
        res = assess_password(pw)
        # print to console
        print(f"{pw!r}: score={res['score']}, time={res['crack_time_display']}, "
              f"warn={res.get('warning')}, suggestions={res.get('suggestions', [])}")
        # append JSON record to file
        write_json_record(out_file, pw, res)
    print(f"\nWrote results to: {out_file}")

if __name__ == "__main__":
    main()
