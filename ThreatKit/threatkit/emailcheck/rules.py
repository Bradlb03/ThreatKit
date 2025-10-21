# threatkit/emailcheck/rules.py
import re
from typing import Dict, List
from urllib.parse import urlparse

# --- Public runner ---

def run_rules(subject: str, from_hdr: str, return_path: str, to_hdr: str, body: str, headers: Dict) -> List[Dict]:
    results: List[Dict] = []
    results.append(rule_sender_mismatch(from_hdr, return_path))
    results.append(rule_urgency_keywords(body))
    results.append(rule_ip_links(body))              # keep this behavior stable
    results.append(rule_suspicious_attachments(body))
    results.append(rule_all_caps_subject(subject))
    return [r for r in results if r is not None]

# --- Individual rules ---

def rule_sender_mismatch(from_hdr: str, return_path: str) -> Dict:
    """
    Compare domain(From) vs domain(Return-Path). If both present and differ -> score.
    (Does not require Reply-To; matches your prior preference.)
    """
    d_from = extract_domain(from_hdr)
    d_rp = extract_domain(return_path)
    if not d_from or not d_rp:
        return {"id": "sender_mismatch", "score": 0, "reason": "Insufficient headers for sender-domain check"}

    if d_from != d_rp:
        return {
            "id": "sender_mismatch",
            "score": 30,
            "reason": f"From domain ({d_from}) does not match Return-Path domain ({d_rp})",
            "evidence": [f"from={d_from}", f"return_path={d_rp}"]
        }
    return {"id": "sender_mismatch", "score": 0, "reason": "From and Return-Path domains match"}

def rule_urgency_keywords(body: str) -> Dict:
    # Tunable list; lightweight and transparent
    keywords = [
        "verify", "immediately", "urgent", "update now", "account suspended",
        "action required", "confirm your password", "limited time"
    ]
    found = []
    for kw in keywords:
        if re.search(rf"\b{re.escape(kw)}\b", body, flags=re.IGNORECASE):
            found.append(kw)
    if found:
        return {
            "id": "urgency_keywords",
            "score": 20,
            "reason": f"Urgency keywords detected: {', '.join(found[:5])}",
            "evidence": found[:5]
        }
    return {"id": "urgency_keywords", "score": 0, "reason": "No urgency phrasing detected"}

def rule_ip_links(body: str) -> Dict:
    """
    Flag links that use a raw IPv4 address (classic phishing tell).
    Examples: http://123.45.67.89/login
    """
    # Simple IPv4 matcher in a URL; avoids false positives in plain text IPs without http(s)
    ip_links = re.findall(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[/:][^\s<>\"]*)?", body)
    if ip_links:
        return {
            "id": "ip_link",
            "score": 25,
            "reason": "Link(s) using raw IP address detected",
            "evidence": ip_links[:5]
        }
    return {"id": "ip_link", "score": 0, "reason": "No raw-IP links detected"}

def rule_suspicious_attachments(body: str) -> Dict:
    """
    Naive indicator: references to risky executable extensions in the message text.
    (If/when you parse real MIME parts, adapt this to true attachment metadata.)
    """
    if re.search(r"\.(exe|scr|js|bat|vbs|jar)\b", body, flags=re.IGNORECASE):
        return {
            "id": "suspicious_attachment",
            "score": 25,
            "reason": "Executable attachment extension mentioned",
            "evidence": ["exe/scr/js/bat/vbs/jar"]
        }
    return {"id": "suspicious_attachment", "score": 0, "reason": "No risky attachment extensions referenced"}

def rule_all_caps_subject(subject: str) -> Dict:
    """
    Heuristic: heavy ALL-CAPS subjects can indicate urgency/spammy patterns.
    """
    subj = subject.strip()
    if subj and len(subj) >= 6 and subj.upper() == subj and re.search(r"[A-Z]", subj):
        return {
            "id": "all_caps_subject",
            "score": 10,
            "reason": "Subject line is ALL CAPS which can indicate urgency/spam"
        }
    return {"id": "all_caps_subject", "score": 0, "reason": "Subject casing looks normal"}

# --- Helpers (shared with detector) ---

def extract_domain(value: str) -> str:
    if not value:
        return ""
    # Try email style first
    m = re.search(r"@([A-Za-z0-9\.-]+\.[A-Za-z]{2,})", value)
    if m:
        return m.group(1).lower()
    # Fallback to URL
    try:
        return urlparse(value).netloc.lower()
    except Exception:
        return value.strip().lower()

def extract_links(body: str) -> List[str]:
    # Simple http(s) URL pluck; good enough for highlights and raw output
    return re.findall(r"https?://[^\s<>\"]+", body)