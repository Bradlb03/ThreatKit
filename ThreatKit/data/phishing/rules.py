import re

# ------------------------------
# Rule 1: Sender mismatch (From vs Return-Path)
# ------------------------------
def rule_sender_mismatch(email):
    if email.get("from") and email.get("return_path"):
        from_dom = email["from"].split("@")[-1].lower()
        rp_dom = email["return_path"].split("@")[-1].lower()
        if from_dom != rp_dom:
            return True, "Sender mismatch: From header does not match Return-Path."
    return False, None


# ------------------------------
# Rule 2: Urgency keywords (Subject or Body)
# ------------------------------
def rule_urgency_keywords(email):
    keywords = ["verify", "urgent", "account suspended", "confirm now", "locked", "limited time", "expires"]
    subject_body = (email.get("subject", "") + " " + email.get("body", "")).lower()
    for kw in keywords:
        if kw in subject_body:
            return True, f"Urgency keywords detected (e.g., '{kw}')."
    return False, None


# ------------------------------
# Rule 3: Suspicious links (raw IP addresses)
# ------------------------------
def rule_ip_links(email):
    body = email.get("body", "") or ""
    # Use mentor's original pattern
    ip_pattern = r"http[s]?://\d{1,3}(\.\d{1,3}){3}"
    if re.search(ip_pattern, body):
        return True, "Suspicious links: email body includes a link with a raw IP address."
    return False, None


# ------------------------------
# Rule 4: Risky attachments
# ------------------------------
def rule_risky_attachments(email):
    risky_ext = [".exe", ".scr", ".bat"]
    for att in email.get("attachments", []) or []:
        if any(att.lower().endswith(ext) for ext in risky_ext):
            return True, f"Risky attachment detected: '{att}'."
    return False, None


# ------------------------------
# run_rules (original behavior)
# ------------------------------
def run_rules(email):
    rules = [rule_sender_mismatch, rule_urgency_keywords, rule_ip_links, rule_risky_attachments]
    results = []
    for rule in rules:
        flag, explanation = rule(email)
        if flag and explanation:
            results.append(explanation)
    return results


# ------------------------------
# Numeric risk scoring
# ------------------------------
RULE_WEIGHTS = {
    "rule_sender_mismatch": 20,
    "rule_urgency_keywords": 15,
    "rule_ip_links": 25,
    "rule_risky_attachments": 40,
}

def analyze(email, threshold=30):
    """
    Run rules, compute risk_score, and return a dictionary with results.
    """
    rules = [rule_sender_mismatch, rule_urgency_keywords, rule_ip_links, rule_risky_attachments]

    per_rule = []
    total = 0
    explanations = []

    for rule in rules:
        name = rule.__name__
        flag, explanation = rule(email)
        weight = RULE_WEIGHTS.get(name, 0) if flag else 0
        if flag and explanation:
            explanations.append(explanation)
        per_rule.append({
            "name": name,
            "triggered": bool(flag),
            "score": weight,
            "explanation": explanation
        })
        total += weight

    risk_score = max(0, min(100, int(total)))
    return {
        "risk_score": risk_score,
        "flag": risk_score >= threshold,
        "threshold": threshold,
        "explanations": explanations,
        "per_rule": per_rule,
    }


# ------------------------------
# Pretty-print results
# ------------------------------
def format_results(results):
    """
    Produce a human-friendly multi-line string from analyze() results.
    """
    lines = []
    lines.append(f"Risk Score: {results.get('risk_score')}")
    lines.append(f"Flagged: {results.get('flag')} (threshold={results.get('threshold')})")
    lines.append("Triggered rules:")
    any_triggered = False
    for r in results.get("per_rule", []):
        if r.get("triggered"):
            any_triggered = True
            score = r.get("score", 0)
            expl = r.get("explanation") or r.get("name")
            lines.append(f"  - [{score} pts] {expl}")
    if not any_triggered:
        lines.append("  - None")
    return "\n".join(lines)


# ------------------------------
# Example usage
# ------------------------------
if __name__ == "__main__":
    test_email = {
        "from": "news@news.com",
        "return_path": "news@news.com",
        "subject": "Limited time deal for subscription",
        "body": "Click here: https://news.com/subscription",
        "attachments": [""]
    }

    results = analyze(test_email)
    print(format_results(results))