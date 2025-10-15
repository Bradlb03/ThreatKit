# threatkit/password/routes.py
from flask import Blueprint, render_template, request, jsonify
from .strength import assess_password

bp = Blueprint("password", __name__, url_prefix="/password")

@bp.route("/", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw:
            try:
                # you can pass user_inputs like ["michael", "loutos", email] if you collect them
                result = assess_password(pw)
            except Exception as e:
                result = {"error": str(e)}
    return render_template("password.html", result=result)

@bp.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "password is required"}), 400
    return jsonify(assess_password(pw))
