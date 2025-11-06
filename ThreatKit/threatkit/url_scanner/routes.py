# threatkit/url_scanner/routes.py
from flask import Blueprint, render_template, request
import requests, json
from threatkit.url_scanner.detector import analyze_url_risk
from threatkit.url_scanner.detector import save_result

bp = Blueprint("url_scanner", __name__)
OLLAMA_URL = "http://ollama:11434/api/generate"

@bp.route("/", methods=["GET", "POST"])
def page():
    result = None
    ai_summary = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = analyze_url_risk(url.strip())
            save_result(result)

            try:
                prompt = (
                    f"You are a cybersecurity assistant. "
                    f"Evaluate this URL analysis report and provide a short, educational explanation "
                    f"about whether the URL seems safe or suspicious.\n\n"
                    f"{json.dumps(result, indent=2)}"
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

    return render_template("link.html", report=result, ai_summary=ai_summary)