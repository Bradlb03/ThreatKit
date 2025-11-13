# threatkit/emailcheck/routes.py

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
            # Run phishing analysis (heuristics + ML)
            result = analyze_email(subject, sender, return_path, "", body, {})
            save_result(result, sender=sender, subject=subject)

            # ---- LLM INTERPRETATION (uses safety_score + indicators) ----
            try:
                analysis_json = json.dumps(result, indent=2)

                prompt = (
                    "You are a cybersecurity assistant. Analyze this EMAIL using both the provided analysis data and the actual email content. Use safety_score as an important signal but not the only factor—also consider wording in the subject and body (urgency, threats, payment requests, login prompts), sender credibility, domain mismatch, link risks, and key indicators. Respond in this exact format: First line: \"This email is likely <Phishing/Legitimate>\". Next up to three short one-line reasons formatted as \"1. <reason>\". Final line: a brief one-sentence summary combining the most important signals. Here is the analysis data: " + analysis_json
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

    return render_template("email.html", result=result, ai_summary=ai_summary)


@bp.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    sender = data.get("from", "").strip()
    return_path = data.get("return_path", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    to_hdr = data.get("to", "").strip()
    headers = data.get("headers", {}) or {}

    if not subject and not body:
        return jsonify({"error": "Email subject or body is required"}), 400

    # Run phishing analysis (heuristics + ML)
    result = analyze_email(subject, sender, return_path, to_hdr, body, headers)
    save_result(result, sender=sender, subject=subject, body=body)

    # ---- LLM INTERPRETATION FOR API CLIENTS ----
    ai_summary = None
    try:
        analysis_json = json.dumps(result, indent=2)

        prompt = (
            "You are a cybersecurity assistant. Analyze this EMAIL using the provided analysis data. "
            "Use the safety_score as your primary source of truth, followed by key_indicators, sender "
            "analysis, link evaluation, and ML probability scores. Base all reasoning on these signals "
            "only—do not guess beyond the data.\n\n"
            "Respond in this exact format:\n"
            "Line 1: \"This email is likely Phishing/Legitimate\" (choose based mainly on safety_score)\n"
            "Next up to six lines: numbered reasons such as "
            "\"1. <short reason based on score, indicators, links, keywords, or domain issues>\"\n"
            "Final line: a brief summary sentence reinforcing the safety_score and main risk factors.\n\n"
            "Here is the analysis data:\n"
            f"{analysis_json}"
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

    # Attach AI explanation to result
    result["ai_summary"] = ai_summary

    return jsonify(result)