# threatkit/emailcheck/rules.py
import re
from typing import Dict, List
from urllib.parse import urlparse

# --- Public runner ---

def run_rules(subject: str, from_hdr: str, return_path: str, to_hdr: str, body: str, headers: Dict) -> List[Dict]:
    results: List[Dict] = []
    results.append(rule_sender_mismatch(from_hdr, return_path))
    results.append(rule_urgency_keywords(body))
    results.append(rule_credential_lifecycle(subject, body))   
    results.append(rule_link_profile(body))                    
    results.append(rule_suspicious_attachments(body))
    results.append(rule_all_caps_subject(subject))
    return [r for r in results if r is not None]

# --- Individual rules ---

def rule_sender_mismatch(from_hdr: str, return_path: str) -> Dict:
    d_from = extract_domain(from_hdr)
    d_rp = extract_domain(return_path)
    if not d_from or not d_rp:
        return {"id": "sender_mismatch", "score": 0, "reason": "Insufficient headers for sender-domain check"}

    if d_from != d_rp:
        return {
            "id": "sender_mismatch",
            "score": 18,  
            "reason": f"From domain ({d_from}) does not match Return-Path domain ({d_rp})",
            "evidence": [f"from={d_from}", f"return_path={d_rp}"]
        }
    return {"id": "sender_mismatch", "score": 0, "reason": "From and Return-Path domains match"}

def rule_urgency_keywords(body: str) -> Dict:
    """
    Variant-aware regex families; catches urgent/urgently/urgency, verify/verification/etc.
    Keeps score modest and capped by count.
    """
    text = body or ""
    patterns = [
        r"\burgent(?:ly|cy)?\b",
        r"\bimmediat(?:e|ely)\b",
        r"\bact (?:now|immediately|today)\b",
        r"\bverif(?:y|ication|ied|ying)\b",
        r"\baccount (?:lock(?:ed)?|suspend(?:ed|s)?|restrict(?:ed)?)\b",
        r"\bconfirm (?:your )?(?:password|details|identity)\b",
        r"\blast (?:warning|notice)\b",
        r"\blimited (?:time|offer)\b",
        r"\baction required\b",
        r"\bclick (?:here|the link)\b",
    ]

    hits = []
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            hits.append(p)

    if hits:
        scores = [8, 4, 2]
        s = sum(scores[:min(len(hits), len(scores))])
        return {
            "id": "urgency_keywords",
            "score": s, 
            "reason": f"Urgency/pressure phrasing detected ({min(len(hits),3)}+ patterns)",
            "evidence": hits[:5]
        }
    return {"id": "urgency_keywords", "score": 0, "reason": "No urgency phrasing detected"}

def rule_credential_lifecycle(subject: str, body: str) -> Dict:
    """
    Flags 'password expire/reset/update' style lures in subject or body.
    Mild–moderate scoring (capped) so legit reminders don't go straight to 0–1.
    """
    text = f"{subject or ''}\n{body or ''}"
    patterns = [
        r"\bpassword(?:s)? (?:will )?expir(?:e|ation)\b",
        r"\breset (?:your )?password\b",
        r"\bupdate (?:your )?password\b",
        r"\bcredential(?:s)? (?:will )?expir(?:e|ation)\b",
    ]
    hits = sum(1 for p in patterns if re.search(p, text, flags=re.IGNORECASE))

    soft_deadline = bool(re.search(r"\bbefore (?:the )?(?:end of|tomorrow|today|monday|tuesday|wednesday|thursday|friday|week)\b",
                                   text, re.IGNORECASE))

    if hits or soft_deadline:
        score = min(12, (8 if hits >= 1 else 0) + (4 if hits >= 2 else 0)) + (2 if soft_deadline else 0)
        score = min(score, 14)
        return {
            "id": "credential_lifecycle",
            "score": score,
            "reason": "Password/credential expiration/reset/update language detected",
        }
    return {"id": "credential_lifecycle", "score": 0, "reason": "No password/credential lifecycle phrasing"}

def rule_link_profile(body: str) -> Dict:
    """
    Counts links, flags raw-IP links heavier, and caps impact.
    """
    text = body or ""
    urls = re.findall(r"https?://[^\s<>\"]+", text)
    n = len(urls)


    ip_links = [u for u in urls if re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[/:]|$)", u)]
    n_ip = len(ip_links)

    score = 0

    if n >= 1:
        score += 4
        if n >= 2: score += 2
        if n >= 3: score += 2  


    if n_ip >= 1:
        score += 8
        if n_ip >= 2: score += 4  

    score = min(score, 14)

    if score > 0:
        reason_bits = [f"{n} link(s)"]
        if n_ip: reason_bits.append(f"{n_ip} raw-IP link(s)")
        return {
            "id": "link_profile",
            "score": score,
            "reason": " / ".join(reason_bits),
            "evidence": urls[:5]
        }
    return {"id": "link_profile", "score": 0, "reason": "No links"}

def rule_suspicious_attachments(body: str) -> Dict:
    if re.search(r"\.(exe|scr|js|bat|vbs|jar)\b", body or "", flags=re.IGNORECASE):
        return {
            "id": "suspicious_attachment",
            "score": 12,  
            "reason": "Executable attachment extension mentioned",
            "evidence": ["exe/scr/js/bat/vbs/jar"]
        }
    return {"id": "suspicious_attachment", "score": 0, "reason": "No risky attachment extensions referenced"}

def rule_all_caps_subject(subject: str) -> Dict:
    subj = (subject or "").strip()
    if subj and len(subj) >= 6 and subj.upper() == subj and re.search(r"[A-Z]", subj):
        return {"id": "all_caps_subject", "score": 6, "reason": "ALL-CAPS subject (urgency/spam cue)"}
    return {"id": "all_caps_subject", "score": 0, "reason": "Subject casing looks normal"}


def extract_domain(value: str) -> str:
    if not value:
        return ""
    m = re.search(r"@([A-Za-z0-9\.-]+\.[A-Za-z]{2,})", value)
    if m:
        return m.group(1).lower()
    try:
        return urlparse(value).netloc.lower()
    except Exception:
        return (value or "").strip().lower()

def extract_links(body: str) -> List[str]:
    return re.findall(r"https?://[^\s<>\"]+", body or "")