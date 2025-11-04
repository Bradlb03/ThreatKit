from flask import Blueprint, render_template, request
import requests
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
                prompt = f"Summarize this phishing analysis and provide recommendations:\n{report}"
                response = requests.post(
                    OLLAMA_URL,
                    json={"model": "granite4:micro", "prompt": prompt},
                    timeout=60
                )
                if response.ok:
                    data = response.json()
                    # Ollama streams responses by default, but the final text is in 'response'
                    ai_summary = data.get("response", "No AI output received.")
                else:
                    ai_summary = f"Error from AI: {response.status_code}"
            except Exception as e:
                ai_summary = f"Error contacting AI model: {e}"

    return render_template("link.html", report=report, ai_summary=ai_summary)
