from flask import Blueprint, render_template
bp = Blueprint("emailcheck", __name__)

@bp.route("/")
def page():
    return render_template("email.html")
