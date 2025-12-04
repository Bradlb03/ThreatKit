# threatkit/emailcheck/routes.py

from flask import Blueprint, render_template, request, jsonify
from .detector import analyze_email, save_result

import json
import requests
import email as email_lib
from email import policy

OLLAMA_URL = "http://ollama:11434/api/generate"

bp = Blueprint("emailcheck", __name__, url_prefix="/phishing")

ALLOWED_EML_EXTENSIONS = {".eml"}


def _allowed_eml(filename: str) -> bool:
    filename = (filename or "").lower()
    return filename.endswith(".eml")


def _parse_eml_file(file_storage):
    raw_bytes = file_storage.read()
    file_storage.seek(0)

    msg = email_lib.message_from_bytes(raw_bytes, policy=policy.default)

    subject = msg.get("Subject", "") or ""
    sender = msg.get("From", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    to_hdr = msg.get("To", "") or ""
    headers = dict(msg.items())

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if ctype == "text/plain" and disp != "attachment":
                body = part.get_content()
                break
        if not body:
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get_content_disposition()
                if ctype.startswith("text/") and disp != "attachment":
                    body = part.get_content()
                    break
    else:
        body = msg.get_content() or ""

    return subject, sender, return_path, to_hdr, body, headers


@bp.route("/", methods=["GET", "POST"])
def phishing_page():
    result = None
    ai_summary = None

    if request.method == "POST":
        # 1) Check for .eml upload FIRST
        eml_file = request.files.get("eml_file")
        if eml_file and eml_file.filename:
            if not _allowed_eml(eml_file.filename):
                result = {"error": "Only .eml files are allowed."}
            else:
                try:
                    subject, sender, return_path, to_hdr, body, headers = _parse_eml_file(eml_file)
                except Exception:
                    result = {"error": "Failed to parse .eml file."}
                else:
                    if not subject and not body:
                        result = {
                            "error": "Uploaded .eml file has no subject or body to analyze."
                        }
                    else:
                        result = analyze_email(subject, sender, return_path, to_hdr, body, headers)
                        save_result(result, sender=sender, subject=subject)

                        # LLM interpretation (same prompt style as before)
                        try:
                            analysis_json = json.dumps(result, indent=2)
                            prompt = (
                                "You are a cybersecurity assistant. Focus primarily on the email's subject and body text to detect phishing, "
                                "calling out specific phrases, requests, links, sender details, or formatting that seem risky or safe. "
                                "Use the provided safety_score, key_indicators, and model/rule outputs only as guidance to support your judgment, "
                                "not as strict rules. The safety_score ranges from 0 to 5, where 0 means extremely unsafe/phishing and 5 means very safe. "
                                "Treat 0 as highly dangerous. Pay special attention to urgency, threats, password or payment requests, login prompts, "
                                "account verification links, and mismatched sender information. Respond in this exact format: first line: "
                                "\"This email is likely <Phishing/Legitimate>\". Next up to three short one-line reasons formatted as \"1. <reason>\" "
                                "that each reference concrete evidence from the email (for example, quoted wording or specific URLs). Final line: "
                                "a brief one-sentence summary combining the most important signals. Here is the email content and analysis data: "
                                "Subject: " + subject + " From: " + sender + " Body: " + body + " Analysis JSON: " + analysis_json
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

        # 2) No file uploaded → fall back to ORIGINAL manual input behavior
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
                    "You are a cybersecurity assistant. Focus primarily on the email's subject and body text to detect phishing, "
                    "calling out specific phrases, requests, links, sender details, or formatting that seem risky or safe. "
                    "Use the provided safety_score, key_indicators, and model/rule outputs only as guidance to support your judgment, "
                    "not as strict rules. The safety_score ranges from 0 to 5, where 0 means extremely unsafe/phishing and 5 means very safe. "
                    "Treat 0 as highly dangerous. Pay special attention to urgency, threats, password or payment requests, login prompts, "
                    "account verification links, and mismatched sender information. Respond in this exact format: first line: "
                    "\"This email is likely <Phishing/Legitimate>\". Next up to three short one-line reasons formatted as \"1. <reason>\" "
                    "that each reference concrete evidence from the email (for example, quoted wording or specific URLs). Final line: "
                    "a brief one-sentence summary combining the most important signals. Here is the email content and analysis data: "
                    "Subject: " + subject + " From: " + sender + " Body: " + body + " Analysis JSON: " + analysis_json
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
            "You are a cybersecurity assistant. Focus primarily on the email's subject and body text to detect phishing,"
            "calling out specific phrases, requests, links, sender details, or formatting that seem risky or safe."
            "Use the provided safety_score, key_indicators, and model/rule outputs only as guidance to support your judgment,"
            "not as strict rules. The safety_score ranges from 0 to 5, where 0 means extremely unsafe/phishing and 5 means very"
            "safe. Treat 0 as highly dangerous. Pay special attention to urgency, threats, password or payment requests, login"
            "prompts, account verification links, and mismatched sender information. Respond in this exact format: first line:"
            "\"This email is likely <Phishing/Legitimate>\". Next up to three short one-line reasons formatted as \"1. <reason>\""
            "that each reference concrete evidence from the email (for example, quoted wording or specific URLs). Final line:"
            "a brief one-sentence summary combining the most important signals. Here is the email content and analysis data:"
            "Subject: " + subject + " From: " + sender + " Body: " + body + " Analysis JSON: " + analysis_json
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


@bp.route("/api/check-eml", methods=["POST"])
def api_check_eml():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if not file or not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not _allowed_eml(file.filename):
        return jsonify({"error": "Only .eml files are supported"}), 400

    try:
        subject, sender, return_path, to_hdr, body, headers = _parse_eml_file(file)
    except Exception:
        return jsonify({"error": "Failed to parse .eml file"}), 400

    if not subject and not body:
        return jsonify({"error": "Email subject or body is required"}), 400

    # Run phishing analysis (heuristics + ML)
    result = analyze_email(subject, sender, return_path, to_hdr, body, headers)
    save_result(result, sender=sender, subject=subject, body=body)

    # LLM interpretation, same pattern as api_check
    ai_summary = None
    try:
        analysis_json = json.dumps(result, indent=2)
        prompt = (
            "You are a cybersecurity assistant. Focus primarily on the email's subject and body text to detect phishing,"
            "calling out specific phrases, requests, links, sender details, or formatting that seem risky or safe."
            "Use the provided safety_score, key_indicators, and model/rule outputs only as guidance to support your judgment,"
            "not as strict rules. The safety_score ranges from 0 to 5, where 0 means extremely unsafe/phishing and 5 means very"
            "safe. Treat 0 as highly dangerous. Pay special attention to urgency, threats, password or payment requests, login"
            "prompts, account verification links, and mismatched sender information. Respond in this exact format: first line:"
            "\"This email is likely <Phishing/Legitimate>\". Next up to three short one-line reasons formatted as \"1. <reason>\""
            "that each reference concrete evidence from the email (for example, quoted wording or specific URLs). Final line:"
            "a brief one-sentence summary combining the most important signals. Here is the email content and analysis data:"
            "Subject: " + subject + " From: " + sender + " Body: " + body + " Analysis JSON: " + analysis_json
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

    result["ai_summary"] = ai_summary

    return jsonify(result)