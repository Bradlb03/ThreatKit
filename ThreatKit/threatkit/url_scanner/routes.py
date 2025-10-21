from flask import Blueprint, render_template, request
bp = Blueprint("url_scanner", __name__)
from threatkit.url_scanner.heuristics import analyze_url

@bp.route("/", methods=["GET", "POST"])
def page():
    report = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            report = analyze_url(url.strip())
    return render_template("link.html")