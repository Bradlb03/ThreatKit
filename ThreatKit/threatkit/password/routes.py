# threatkit/password/routes.py
from flask import Blueprint, render_template, request, jsonify
from .strength import assess_password, save_result

import json
import requests

bp = Blueprint("password", __name__, url_prefix="/password")

LABELS_0_4 = {
    0: "Too Weak",
    1: "Very Weak",
    2: "Weak",
    3: "Fair",
    4: "Very Strong",
    5: "Extermely Strong",
}
# Same Ollama endpoint used in emailcheck routes
OLLAMA_URL = "http://ollama:11434/api/generate"


@bp.route("/", methods=["GET", "POST"])
def password_checker():
    result = None
    ai_summary = None

    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw:
            try:
                # Core password analysis
                result = assess_password(pw)
                # Append results (timestamp + analysis only)
                save_result(result)

                # ---- LLM INTERPRETATION (uses password score + analysis) ----
                try:
                    analysis_json = json.dumps(result, indent=2)

                    prompt = (
                        "You are a password security assistant. Use ONLY the information contained "
                        "in the provided analysis JSON to explain the password's strength to a "
                        "non-technical user. Do not infer or guess beyond what the JSON explicitly states. "
                        "Do not repeat the password that is entered. It is confidential"
                        "Consider fields such as score, crack_time_display, warning, and suggestions. "
                        "The score is on a 0-5 basis. 0 would be a low safety score, meaning bad. 5 would be" 
                        "the highest safety scoring, being the safest password"
                        "Respond in this exact format:\n"
                        'First line: "This password is <Very weak/Weak/Moderate/Strong/Very strong>."\n'
                        "Next up to three short one-line reasons formatted as "
                        "'1. <reason>' that each reference specific fields or values from the JSON.\n"
                        "Final line: a brief one-sentence summary giving clear, actionable advice.\n"
                        "Here is the analysis data:\n"
                        f"Analysis JSON: {analysis_json}"
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

            except Exception as e:
                result = {"error": str(e)}

    return render_template("password.html", result=result, ai_summary=ai_summary)


@bp.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "password is required"}), 400
           
    # Core password analysis
    result = assess_password(pw)
    save_result(result)  # log API results too

    # ---- LLM INTERPRETATION FOR API CLIENTS ----
    ai_summary = None
    try:
        analysis_json = json.dumps(result, indent=2)

        prompt = (
            "You are a password security assistant. Use ONLY the information contained "
            "in the provided analysis JSON to explain the password's strength to a "
            "non-technical user. Do not infer or guess beyond what the JSON explicitly states. "
            "Do not repeat the password that is entered. It is confidential"
            "Consider fields such as score, crack_time_display, warning, and suggestions. "
            "The score is on a 0-5 basis. 0 would be a low safety score, meaning bad. 5 would be" 
            "the highest safety scoring, being the safest password"
            "Respond in this exact format:\n"
            'First line: "This password is <Very weak/Weak/Moderate/Strong/Very strong>."\n'
            "Next up to three short one-line reasons formatted as "
            "'1. <reason>' that each reference specific fields or values from the JSON.\n"
            "Final line: a brief one-sentence summary giving clear, actionable advice.\n"
            "Here is the analysis data:\n"
            f"Analysis JSON: {analysis_json}"
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

    # Attach AI explanation to result for API consumers
    result["ai_summary"] = ai_summary

    return jsonify(result)
