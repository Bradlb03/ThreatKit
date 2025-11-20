# threatkit/password/routes.py
from flask import Blueprint, render_template, request, jsonify
from .strength import assess_password, save_result

bp = Blueprint("password", __name__, url_prefix="/password")

LABELS_0_4 = {
    0: "Too Weak",
    1: "very Weak",
    2: "Weak",
    3: "Fair",
    4: "Very Strong",
    5: "Extermely Strong",
}

@bp.route("/", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw:
            try:
                base_result = assess_password(pw) 
                save_result(base_result)
                score = int(base_result.get("score", 0))
                result = dict(base_result)
                result["label"] = LABELS_0_4.get(score, "")
            except Exception as e:
                result = {"error": str(e)}
    return render_template("password.html", result=result)


@bp.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "password is required"}), 400

    result = assess_password(pw)   # unchanged API payload (no label added)
    save_result(result)            
    return jsonify(result)
