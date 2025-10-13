from flask import Blueprint, render_template
bp = Blueprint("password", __name__)

@bp.route("/")
def page():
    return render_template("password.html")
