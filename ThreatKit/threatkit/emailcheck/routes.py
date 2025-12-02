from flask import Blueprint, render_template, request, jsonify
from .detector import analyze_email, save_result

import json
import requests

OLLAMA_URL = "http://ollama:11434/api/generate"

bp = Blueprint("emailcheck", __name__, url_prefix="/phishing")


@bp.route("/", methods=["GET", "POST"])
def phishing_page():
    result = None
    ai_summary = None

    if request.method == "POST":
        sender = request.form.get("from", "").strip()
        return_path = request.form.get("return_path", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if not subject and not body:
            result = {"error": "Please provide at least a subject or body to analyze."}
        else:
            result = analyze_email(subject, sender, return_path, "", body, {})
            save_result(result, sender=sender, subject=subject)

    return render_template("email.html", result=result, ai_summary=None)


@bp.route("/ai", methods=["GET"])
def ai_summary():
    subject = request.args.get("subject", "")
    sender = request.args.get("sender", "")
    return_path = request.args.get("return_path", "")
    body = request.args.get("body", "")
    result_json = request.args.get("result_json", "{}")

    try:
        result = json.loads(result_json)
    except:
        return "<div class='tk-card mt-4'><div class='tk-subtle'>Invalid data</div></div>"

    try:
        prompt = (
            "You are a cybersecurity assistant. Focus primarily on the email's subject and body "
            "to detect phishing. Respond with: first line 'This email is likely <Phishing/Legitimate>'. "
            "Then up to three short numbered reasons. Final line: one-sentence summary.\n"
            f"Subject: {subject}\nFrom: {sender}\nBody: {body}\nAnalysis JSON:\n{result_json}"
        )

        with requests.post(
            OLLAMA_URL,
            json={"model": "granite4:micro", "prompt": prompt},
            stream=True,
            timeout=120,
        ) as response:
            response.raise_for_status()
            text = ""
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode("utf-8"))
                        text += data.get("response", "")
                    except:
                        continue
    except Exception as e:
        text = f"Error contacting AI model: {e}"

    return (
        "<div id='ai-summary' class='tk-card mt-4'>"
        "<div class='fw-semibold mb-2'>AI Analysis Summary</div>"
        f"<div class='tk-subtle' style='white-space: pre-wrap;'>{text}</div>"
        "</div>"
    )