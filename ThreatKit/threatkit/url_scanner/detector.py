from typing import Dict, Optional
from pathlib import Path
from datetime import datetime
import json
from .heuristics import analyze_url

# Import the model wrapper
try:
    from .model_wrapper import predict_url
    ML_AVAILABLE = True
except Exception:
    predict_url = None
    ML_AVAILABLE = False


def analyze_url_risk(url: str) -> Dict:
    heuristics = analyze_url(url)
    ml = None
    risk_score = 0
    threshold = 40

    BASELINE_SHIFT = 0.0
    SCALE = 1.0
    HEURISTIC_BOOST = 0.15  # +15% if heuristics detect risk

    if ML_AVAILABLE:
        try:
            ml = predict_url(url)
            probs = ml.get("all_probabilities") or {}

            phishing_prob = sum(p for lbl, p in probs.items() if "phishing" in lbl.lower())
            legit_prob = sum(p for lbl, p in probs.items() if "legit" in lbl.lower())

            if phishing_prob == 0 and legit_prob > 0:
                phishing_prob = 1.0 - legit_prob

            calibrated = (phishing_prob + BASELINE_SHIFT) * SCALE

            if heuristics.get("suspicious"):
                calibrated += HEURISTIC_BOOST

            risk_score = int(round(min(1.0, calibrated) * 100))

        except Exception as e:
            ml = {"error": str(e)}

    if not ML_AVAILABLE or (ml and ml.get("error")):
        risk_score = 50 if heuristics.get("suspicious") else 10

    result = {
        "url": url,
        "risk_score": risk_score,
        "flag": risk_score >= threshold,
        "threshold": threshold,
        "heuristics": heuristics,
        "ml": None
        if not ml
        else {
            "prediction": ml.get("prediction"),
            "confidence": ml.get("confidence"),
            "error": ml.get("error") if "error" in ml else None,
        },
    }
    return result


# Optional markdown logging
_RESULTS_MD = Path(__file__).resolve().parent / "results" / "url_analysis.md"


def save_result(result: Dict) -> Path:
    """Save each URL analysis to Markdown for recordkeeping."""
    _RESULTS_MD.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    url = result.get("url")
    lines = [
        f"## {ts} UTC",
        f"- **URL:** {url}",
        f"- **Risk score:** {result.get('risk_score')} / 100 — {'PHISHING' if result.get('flag') else 'Likely safe'}",
        f"- **Threshold:** {result.get('threshold')}",
    ]

    ml = result.get("ml") or {}
    if ml.get("error"):
        lines.append(f"- **ML:** error — `{ml['error']}`")
    else:
        if ml.get("prediction"):
            lines.append(f"- **ML prediction:** {ml['prediction']}")
        if ml.get("confidence") is not None:
            lines.append(f"- **ML confidence:** {ml['confidence']:.2%}")

    heuristics = result.get("heuristics") or {}
    if heuristics:
        lines.append(f"- **Heuristic findings:** `{json.dumps(heuristics, indent=2)}`")

    with _RESULTS_MD.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n\n---\n")

    return _RESULTS_MD