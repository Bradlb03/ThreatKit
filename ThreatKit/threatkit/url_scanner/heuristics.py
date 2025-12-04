import re
from urllib.parse import urlparse
import socket
import dns.resolver

CONFIG = {
    "max_length": 70,
    "suspicious_tlds": {".xyz", ".top", ".click", ".info", ".country", ".cc", ".shop", ".app", ".site", ".php", ".run", ".icu", ".ba", ".me", ".store"},
    "max_subdomains": 1,
    "dns_public_resolver": "8.8.8.8",
}

def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return {
            "name": "Insecure Protocol (HTTP)",
            "triggered": True,
            "reason": "URL uses plain HTTP instead of HTTPS, which can expose users to phishing or interception.",
            "reference": "HTTPS ensures encryption and authenticity. HTTP sites are often targeted for phishing."
        }
    return {"name": "Insecure Protocol (HTTP)", "triggered": False}

def check_suspicious_tld(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    for tld in CONFIG["suspicious_tlds"]:
        if domain.endswith(tld):
            return {
                "name": "Suspicious TLD",
                "triggered": True,
                "reason": f"Domain ends with '{tld}', a TLD frequently used for phishing or spam.",
                "reference": "Low-cost TLDs like .xyz, .top, .click, .info, and .country are often abused in phishing campaigns."
            }
    return {"name": "Suspicious TLD", "triggered": False}

def check_at_symbol(url):
    if "@" in url:
        return {
            "name": "Contains '@' Symbol",
            "triggered": True,
            "reason": "URL contains an '@' character, which can obscure the real destination of a link.",
            "reference": "Attackers often use 'user@domain.com' patterns to mislead users (OWASP URL Security Cheatsheet)."
        }
    return {"name": "Contains '@' Symbol", "triggered": False}

def check_length(url):
    if len(url) > CONFIG["max_length"]:
        return {
            "name": "Excessive URL Length",
            "triggered": True,
            "reason": f"URL length ({len(url)}) exceeds {CONFIG['max_length']} characters, potentially hiding malicious content.",
            "reference": "Very long URLs are often padded to conceal redirect chains or tracking parameters."
        }
    return {"name": "Excessive URL Length", "triggered": False}

def check_subdomains(url):
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    if len(parts) - 2 > CONFIG["max_subdomains"]:
        return {
            "name": "Excessive Subdomains",
            "triggered": True,
            "reason": f"URL contains many subdomains ({len(parts) - 2}), which may be used to mimic legitimate sites.",
            "reference": "Phishing URLs often use misleading subdomains (e.g., login.security.update.example.com)."
        }
    return {"name": "Excessive Subdomains", "triggered": False}

def check_dns_poisoning(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]

    try:
        local_ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "name": "DNS Resolution Failure",
            "triggered": True,
            "reason": "Domain could not be resolved locally, which may indicate DNS issues.",
            "reference": "DNS failures can occur due to tampering or misconfiguration."
        }

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [CONFIG["dns_public_resolver"]]
        answers = resolver.resolve(domain, "A")
        public_ip = answers[0].to_text()
    except Exception:
        return {
            "name": "Public DNS Lookup Failed",
            "triggered": True,
            "reason": "Public DNS resolver could not resolve the domain.",
            "reference": "Failure to resolve via public DNS may indicate DNS manipulation."
        }

    if local_ip != public_ip:
        return {
            "name": "Possible DNS Poisoning",
            "triggered": True,
            "reason": f"Local DNS returned {local_ip}, but public DNS returned {public_ip}.",
            "reference": "DNS poisoning occurs when attackers tamper with DNS results to redirect traffic."
        }

    return {"name": "Possible DNS Poisoning", "triggered": False}

def analyze_url(url):
    checks = [
        check_https(url),
        check_suspicious_tld(url),
        check_at_symbol(url),
        check_length(url),
        check_subdomains(url),
        check_dns_poisoning(url),
    ]

    triggered = [c for c in checks if c["triggered"]]
    score = 5 - len([c for c in checks if c["triggered"] and c["name"] != "Public DNS Lookup Failed" and c["name"] != "DNS Resolution Failure"])

    return {
        "url": url,
        "score": score,
        "results": checks,
        "triggered": triggered,
    }

if __name__ == "__main__":
    test_urls = [
        "http://example.com",
        "https://safe-site.org",
        "https://login.security.update.example.com",
        "https://malicious.click/path?param=value",
        "https://reallylongdomainnameexamplethatgoesonforeverandever.com/some/path",
        "https://user@evil.xyz/login"
    ]

    for u in test_urls:
        report = analyze_url(u)
        print(f"\nURL: {report['url']}")
        print(f"Score: {report['score']}")
        for item in report["triggered"]:
            print(f" - {item['name']}: {item['reason']}")