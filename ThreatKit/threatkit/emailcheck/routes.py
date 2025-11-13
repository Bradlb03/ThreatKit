# threatkit/emailcheck/routes.py (snippet)
from flask import Blueprint, render_template, request, jsonify
from .detector import analyze_email, save_result

bp = Blueprint("emailcheck", __name__, url_prefix="/phishing")

@bp.route("/", methods=["GET", "POST"])
def phishing_page():
    result = None
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

    return render_template("email.html", result=result)

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

    result = analyze_email(subject, sender, return_path, to_hdr, body, headers)
    save_result(result, sender=sender, subject=subject, body=body)
    return jsonify(result)