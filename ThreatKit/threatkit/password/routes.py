# threatkit/password/routes.py
from flask import Blueprint, render_template, request, jsonify
from .strength import assess_password, save_result  # import save_result

bp = Blueprint("password", __name__, url_prefix="/password")

@bp.route("/", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw:
            try:
                result = assess_password(pw)
                # append results (timestamp + analysis only)
                save_result(result)
            except Exception as e:
                result = {"error": str(e)}
    return render_template("password.html", result=result)


@bp.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "password is required"}), 400

    result = assess_password(pw)
    save_result(result)  # log API results too
    return jsonify(result)
