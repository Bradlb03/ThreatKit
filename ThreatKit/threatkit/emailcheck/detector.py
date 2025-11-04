# threatkit/emailcheck/detector.py
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import json

from .rules import run_rules, extract_links, extract_domain

# Try to import the Hugging Face model wrapper
try:
    from .model_wrapper import predict_email_text
    ML_AVAILABLE = True
except Exception:
    predict_email_text = None
    ML_AVAILABLE = False


def analyze_email(
    subject: str,
    from_hdr: str,
    return_path: str,
    to_hdr: str,
    body: str,
    headers: Optional[Dict] = None
) -> Dict:
    """
    Main analysis pipeline for phishing detection.

    - Primary risk score comes from the HF model's phishing probability.
    - Rule-based heuristics provide 'key_indicators' for transparent signals.
    - If ML is unavailable or errors, fallback is a capped sum of rule scores.
    - Returns a compact dict suitable for UI and API.
    """
    headers = headers or {}

    # --- 1) Rule-based checks (for indicators only; they don't dominate score) ---
    rule_outputs: List[Dict] = run_rules(subject, from_hdr, return_path, to_hdr, body, headers)
    key_indicators = [r["reason"] for r in rule_outputs if r.get("score", 0) > 0][:5]

    # --- 2) Model-based risk score (primary) with calibration knobs ---
    ml = None
    risk_score = 0
    threshold = 30

    # Calibration knobs (tune to taste; small boosts recommended)
    RULE_BOOST_PER_HIT = 0.12   # +12% per triggered indicator
    RULE_BOOST_CAP     = 0.36   # cap rule-boost at +36%
    BASELINE_SHIFT     = 0.00   # constant bias to phishing_prob (e.g., +0.05)
    SCALE              = 1.00   # scale phishing_prob (e.g., 1.10 for mild inflation)

    if ML_AVAILABLE:
        try:
            email_text = f"Subject: {subject}\nFrom: {from_hdr}\n\n{body}"
            ml = predict_email_text(email_text)

            # Expect: ml["all_probabilities"] is {label: prob}, with labels like:
            # ["legitimate_email", "phishing_url", "legitimate_url", "phishing_url_alt"]
            probs = ml.get("all_probabilities") or {}

            # 1) Primary phishing prob = sum of all labels containing 'phishing'
            phishing_prob = sum(p for lbl, p in probs.items() if "phishing" in lbl.lower())

            # 2) If still zero but we have 'legitimate' labels, invert the max legitimate prob
            if phishing_prob == 0 and probs:
                legit_prob = max((p for lbl, p in probs.items() if "legitimate" in lbl.lower()), default=0.0)
                phishing_prob = max(0.0, 1.0 - legit_prob)

            # 3) Calibration: baseline shift/scale + bounded rule-boost
            calibrated = phishing_prob
            calibrated = min(1.0, max(0.0, (calibrated + BASELINE_SHIFT) * SCALE))

            hits = sum(1 for r in rule_outputs if r.get("score", 0) > 0)
            rule_boost = min(RULE_BOOST_CAP, RULE_BOOST_PER_HIT * hits)
            calibrated = min(1.0, max(0.0, calibrated + rule_boost))

            risk_score = int(round(calibrated * 100))

        except Exception as e:
            ml = {"error": str(e)}

    # --- 3) Fallback if ML unavailable or errored: simple capped rule sum ---
    if not ML_AVAILABLE or (ml and ml.get("error")):
        rule_sum = sum(max(0, r.get("score", 0)) for r in rule_outputs)
        risk_score = min(100, int(rule_sum))

    # --- 4) Build structured result (minimal fields for UI) ---
    result = {
        "risk_score": risk_score,
        "flag": risk_score >= threshold,
        "threshold": threshold,
        "key_indicators": key_indicators,
        "ml": None
        if not ml
        else {
            "prediction": ml.get("prediction"),
            "confidence": ml.get("confidence"),
            "error": ml.get("error") if "error" in ml else None,
        },
        "raw": {
            "sender_domain": extract_domain(from_hdr),
            "return_path_domain": extract_domain(return_path),
            "parsed_links": extract_links(body),
        },
        # Keep full rules internally (used only for logging/debug)
        "rules": rule_outputs,
    }
    return result


# ---------- Markdown logging (privacy-respecting) in results/ ----------

_RESULTS_MD = Path(__file__).resolve().parent / "results" / "phishing_analysis.md"


def _mask_sender(sender: str) -> str:
    """Mask sender email local-part for privacy."""
    if "@" not in sender or not sender:
        return sender
    local, domain = sender.split("@", 1)
    masked_local = (local[:1] + "*" * max(1, min(3, len(local) - 1))) if local else "*"
    return f"{masked_local}@{domain}"


def save_result(result: Dict, sender: Optional[str] = None, subject: Optional[str] = None) -> Path:
    """
    Append a detailed Markdown entry into results/phishing_analysis.md.
    We do NOT store the email body; we keep only masked sender, subject, domains, top links,
    the model's minimal output, and key indicators—ideal for a follow-on LLM to summarize.
    """
    _RESULTS_MD.parent.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    masked_sender = _mask_sender(sender or "")
    subj = (subject or "")[:200]

    lines = [
        f"## {ts} UTC",
        f"- **Sender (masked):** `{masked_sender}`",
        f"- **Subject:** {subj}",
        f"- **Risk score:** {result.get('risk_score')} / 100 — {'PHISHING' if result.get('flag') else 'Likely safe'}",
        f"- **Threshold:** {result.get('threshold')}",
    ]

    # ML summary (minimal)
    ml = result.get("ml") or {}
    if ml.get("error"):
        lines.append(f"- **ML:** error — `{ml['error']}`")
    else:
        if ml.get("prediction") is not None:
            lines.append(f"- **ML prediction:** {ml['prediction']}")
        if ml.get("confidence") is not None:
            lines.append(f"- **ML confidence:** {ml['confidence']:.2%}")

    # Key indicators from rules
    indicators = result.get("key_indicators") or []
    if indicators:
        lines.append("- **Key indicators:**")
        for ex in indicators:
            lines.append(f"  - {ex}")

    # Domain/link context (no body stored)
    raw = result.get("raw") or {}
    sender_dom = raw.get("sender_domain")
    rp_dom = raw.get("return_path_domain")
    if sender_dom or rp_dom:
        lines.append("- **Domains:**")
        if sender_dom:
            lines.append(f"  - sender_domain: {sender_dom}")
        if rp_dom:
            lines.append(f"  - return_path_domain: {rp_dom}")

    links = (raw.get("parsed_links") or [])[:3]
    if links:
        lines.append("- **Top links:**")
        for link in links:
            lines.append(f"  - {link}")

    # Compact JSON payload for LLMs (no email body)
    compact = {
        "sender_masked": masked_sender,
        "subject": subj,
        "risk_score": result.get("risk_score"),
        "flag": result.get("flag"),
        "threshold": result.get("threshold"),
        "ml": ml,
        "indicators": indicators,
        "domains": {"sender": sender_dom, "return_path": rp_dom},
        "links": links,
    }
    lines.append("\n<details><summary>compact-json</summary>\n\n```json")
    lines.append(json.dumps(compact, indent=2, ensure_ascii=False))
    lines.append("```\n</details>\n\n---\n")

    with _RESULTS_MD.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return _RESULTS_MD