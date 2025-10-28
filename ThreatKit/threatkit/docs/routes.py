# threatkit/docs/routes.py
from flask import Blueprint, render_template

bp = Blueprint("docs", __name__)

@bp.route("/", methods=["GET"])
def index():
    # If you later want multiple pages, pass data into the template here.
    return render_template("docs.html")
