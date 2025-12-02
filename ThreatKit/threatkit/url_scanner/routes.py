from flask import Blueprint, render_template, request
import requests, json
from threatkit.url_scanner.heuristics import analyze_url

bp = Blueprint("url_scanner", __name__)

OLLAMA_URL = "http://ollama:11434/api/generate"

# NEW: score → label map (0–5)
LABELS = {
    0: "Very Poor",
    1: "Poor",
    2: "Fair",
    3: "Good",
    4: "Very Good",
    5: "Excellent",
}

@bp.route("/", methods=["GET", "POST"])
def page():
    report = None
    ai_summary = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            report = analyze_url(url.strip())

            # label for the 0–5 score
            try:
                score = int(report.get("score", 0))
            except Exception:
                score = 0
            report["label"] = LABELS.get(score, "")

            # Pass URL via local API call to Ollama container for analysis
            try:
                prompt = (
                    "You are a cybersecurity assistant. Analyze the following URL for potential risks. Look for misspellings, suspicious domain endings, unusual subdomains, use of URL shorteners, HTTP or HTPPS, or misleading keywords. Respond with the shortest possible educational explanation as to why it may or may not be safe. Always respond in the following format: 'This link is likely Suspicious/Safe' On a new line, no more than six reasons formatted as, '1. <why suspicious/safe reason 1>'. On a new line, brief explanation summarizing points.\n"
                    f"{report}"
                )
                with requests.post(
                    OLLAMA_URL,
                    json={"model": "granite4:micro", "prompt": prompt},
                    stream=True,
                    timeout=120,
                ) as response:
                    response.raise_for_status()
                    ai_summary = ""
                    for line in response.iter_lines():
                        if line:
                            try:
                                data = json.loads(line.decode("utf-8"))
                                ai_summary += data.get("response", "")
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                ai_summary = f"Error contacting AI model: {e}"

    return render_template("link.html", report=report, ai_summary=ai_summary)
