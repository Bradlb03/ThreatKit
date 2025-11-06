from flask import Blueprint, render_template, request
import requests, json
from threatkit.url_scanner.heuristics import analyze_url

bp = Blueprint("url_scanner", __name__)

OLLAMA_URL = "http://ollama:11434/api/generate"

@bp.route("/", methods=["GET", "POST"])
def page():
    report = None
    ai_summary = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            report = analyze_url(url.strip())

            # Send the heuristic analysis to Ollama for interpretation
            try:
                prompt = f"You are a cybersecurity assistant. Analyze the following URL for potential risks. Look for misspellings, suspicious domain endings, unusual subdomains, use of URL shorteners, or misleading keywords. Respond with the shortest possible educational explaination as to why it may or may not be safe. Always respond in the following format: 'Suspicious/Safe' On a new line, '1. <why suspicious/safe reason 1>' On a new line, '2. <why suspicious/safe reason 2>' On a new line, brief explanation summarizing points.\n{report}"
                with requests.post(
                    OLLAMA_URL,
                    json={"model": "granite4:micro", "prompt": prompt},
                    stream=True,
                    timeout=120
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