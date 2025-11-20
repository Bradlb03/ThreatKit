from flask import Blueprint, render_template
bp = Blueprint("linkcheck", __name__)

@bp.route("/")
def page():
    return render_template("link.html")
