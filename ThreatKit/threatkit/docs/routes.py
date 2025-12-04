# threatkit/docs/routes.py
from flask import Blueprint, render_template

bp = Blueprint("docs", __name__)

@bp.route("/", methods=["GET"])
def index():
    return render_template("docs.html")
