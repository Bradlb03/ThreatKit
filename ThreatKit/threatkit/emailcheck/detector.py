# threatkit/emailcheck/detector.py
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import math
import json

from .rules import run_rules, extract_links, extract_domain

try:
    from .model_wrapper import predict_email_text
    ML_AVAILABLE = True
except Exception:
    predict_email_text = None
    ML_AVAILABLE = False


# ---------- Helpers ----------

def _smooth_phishing_prob(p: float, temperature: float = 1.0) -> float:
    """Reduce extreme spikes lightly. temperature=1.0 means minimal smoothing."""
    p = min(1.0, max(0.0, float(p)))
    logit = math.log((p + 1e-9) / (1 - p + 1e-9))
    logit /= max(1e-9, temperature)
    return 1 / (1 + math.exp(-logit))


def _map_prob_to_safe_0_5(p_phish: float) -> float:
    """
    p_phish in [0,1] → SAFE score in [0,5] (higher = safer).
    Use full dynamic range so strongly phishy items can be low (near 0).
    """
    safety = 5.0 * (1.0 - p_phish)        #higher p_phish => lower safety
    return round(max(0.0, min(5.0, safety)), 1)  # clamp and one-decimal


def _squash_rule_sum(rule_sum: float) -> float:
    """
    Squash raw rule sums into a phishing probability 0..1.
    Tuned so higher rule sums map to higher phish probability,
    but uses an exponential curve so small sums are damped.
    """
    x = max(0.0, float(rule_sum))
    return 1.0 - math.exp(-x / 30.0)


# ---------- Core ----------

def analyze_email(subject, from_hdr, return_path, to_hdr, body, headers: Optional[Dict] = None) -> Dict:
    headers = headers or {}

    # Run rules first (for indicators and fallback)
    rule_outputs: List[Dict] = run_rules(subject, from_hdr, return_path, to_hdr, body, headers)
    key_indicators = [r["reason"] for r in rule_outputs if r.get("score", 0) > 0][:5]
    rule_sum = sum(max(0, r.get("score", 0)) for r in rule_outputs)

    ml = None
    p_phish = 0.0  # final phishing probability we’ll compute

    if ML_AVAILABLE:
        try:
            email_text = f"Subject: {subject}\nFrom: {from_hdr}\n\n{body}"
            ml = predict_email_text(email_text)

            probs = ml.get("all_probabilities") or {}
            phishing_prob = sum(p for lbl, p in probs.items() if "phishing" in lbl.lower())

            if phishing_prob == 0 and probs:
                legit_prob = max((p for lbl, p in probs.items() if "legitimate" in lbl.lower()), default=0.0)
                phishing_prob = max(0.0, 1.0 - legit_prob)

            
            p_ml = _smooth_phishing_prob(phishing_prob, temperature=0.9)

            p_rule = 1.0 - math.exp(-rule_sum / 10.0)

            p_phish = 0.45 * p_ml + 0.55 * p_rule
            p_phish = min(1.0, max(0.0, p_phish))

        except Exception as e:
            ml = {"error": str(e)}

    # Fallback to rules-only if ML is unavailable or errored
    if not ML_AVAILABLE or (ml and ml.get("error")):
        p_phish = _squash_rule_sum(rule_sum)

    # Convert phishing probability -> safety score 0–5 (float, one decimal)
    safe_score = _map_prob_to_safe_0_5(p_phish)

    # Category thresholds (0..5 safe score)
    if safe_score < 1.5:
        category = "Phishing"
    elif safe_score < 3.5:
        category = "Likely Phishing"
    else:
        category = "Safe"

    result = {
        "risk_score": safe_score,  # SAFE score 0–5 (float, one decimal)
        "category": category,
        "key_indicators": key_indicators,
        "ml": None if not ml else {
            "prediction": ml.get("prediction"),
            "confidence": ml.get("confidence"),
            "error": ml.get("error") if "error" in ml else None,
        },
        "raw": {
            "sender_domain": extract_domain(from_hdr),
            "return_path_domain": extract_domain(return_path),
            "parsed_links": extract_links(body),
        },
        "rules": rule_outputs,
    }
    return result


# ---------- Logging ----------

_RESULTS_MD = Path(__file__).resolve().parent / "results" / "phishing_analysis.md"

def _mask_sender(sender: str) -> str:
    if "@" not in sender or not sender:
        return sender
    local, domain = sender.split("@", 1)
    masked_local = (local[:1] + "*" * max(1, min(3, len(local) - 1))) if local else "*"
    return f"{masked_local}@{domain}"

def save_result(result: Dict, sender: Optional[str] = None, subject: Optional[str] = None) -> Path:
    _RESULTS_MD.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    masked_sender = _mask_sender(sender or "")
    subj = (subject or "")[:200]

    lines = [
        f"## {ts} UTC",
        f"- **Sender (masked):** `{masked_sender}`",
        f"- **Subject:** {subj}",
        f"- **Safety score:** {result.get('risk_score'):.1f} / 5 — {result.get('category')}",
    ]

    ml = result.get("ml") or {}
    if ml.get("error"):
        lines.append(f"- **ML:** error — `{ml['error']}`")
    else:
        if ml.get("prediction"): lines.append(f"- **ML prediction:** {ml['prediction']}")
        if ml.get("confidence") is not None:
            lines.append(f"- **ML confidence:** {ml['confidence']:.2%}")

    indicators = result.get("key_indicators") or []
    if indicators:
        lines.append("- **Key indicators:**")
        for ex in indicators: lines.append(f"  - {ex}")

    with _RESULTS_MD.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return _RESULTS_MD