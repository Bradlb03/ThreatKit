from flask import Blueprint, render_template, request, jsonify
import requests, json
from threatkit.url_scanner.heuristics import analyze_url

bp = Blueprint("url_scanner", __name__, url_prefix="/url")

OLLAMA_URL = "http://ollama:11434/api/generate"

LABELS = {
    0: "Extremely Suspicious",
    1: "Very Suspicious",
    2: "Fairly Suspicious",
    3: "Suspicious",
    4: "Slightly Suspicious",
    5: "Not Suspicious",
}


@bp.route("/", methods=["GET", "POST"])
def page():
    prefill = request.args.get("url", "").strip()
    report = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            report = analyze_url(url)
            score = int(report.get("score", 0))
            report["label"] = LABELS.get(score, "")
            return render_template("link.html", report=report, prefill=url)

    return render_template("link.html", report=report, prefill=prefill)


@bp.route("/ai_summary", methods=["POST"])
def ai_summary():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url:
        return {"error": "Missing URL"}, 400

    report = analyze_url(url.strip())

    prompt = (
        "You are a cybersecurity assistant. Analyze the URL and the provided URL-safety report. "
        "Base your conclusions only on information actually present in the URL string and the report fields "
        "(score, checks, results). Do not infer or imagine hidden content, destinations, behaviors, or organizations. "
        "Evaluate for: HTTPS vs HTTP, suspicious or uncommon TLDs, misleading or excessive subdomains, abnormal URL length, "
        "special characters, obfuscation, misspellings, and known risky patterns such as URL shorteners or login-related "
        "keywords. Your response must follow this exact format: Line 1: This link is <Not Suspicious/Slightly Suspicious/Suspicious/Fairly Suspicious/Very Suspicious/Extremely Suspicious> "
        "Next lines (maximum of six): '1. <short factual reason>' '2. <short factual reason>' "
        "Final line: One brief summary sentence combining the main signals. "
        "Additional rules: No speculation, no invented context.\n"
        f"{report}"
    )

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": "granite4:micro", "prompt": prompt},
            stream=True,
            timeout=120,
        )
        resp.raise_for_status()

        ai_text = ""
        for line in resp.iter_lines():
            if line:
                try:
                    data = json.loads(line.decode("utf-8"))
                    ai_text += data.get("response", "")
                except:
                    pass

        return {"summary": ai_text}

    except Exception as e:
        return {"summary": f"Error contacting AI model: {e}"}
