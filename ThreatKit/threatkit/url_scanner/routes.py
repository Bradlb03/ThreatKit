from flask import Blueprint, render_template, request
from threatkit.url_scanner.heuristics import analyze_url
from threatkit.url_scanner.model import classify_url  # local model interface

bp = Blueprint("url_scanner", __name__)

@bp.route("/", methods=["GET", "POST"])
def page():
    report = None
    ai_result = None
    ai_summary = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            url = url.strip()
            # Heuristic checks
            report = analyze_url(url)
            # Local AI classification
            ai_result = classify_url(url)

            # Create a short summary based on classification result
            label = ai_result["label"]
            confidence = ai_result["confidence"]

            if label == "official_website":
                ai_summary = (
                    f"This URL appears to belong to an official or verified website "
                    f"(confidence {confidence*100:.1f}%). "
                    "It shows normal structure and common domain patterns."
                )
            elif label == "platform":
                ai_summary = (
                    f"This URL is recognized as belonging to an online platform "
                    f"(confidence {confidence*100:.1f}%). "
                    "It may still host user-generated content, so caution is advised."
                )
            else:
                ai_summary = (
                    f"The model could not confidently classify this URL "
                    f"(confidence {confidence*100:.1f}%). "
                    "Manual inspection is recommended."
                )

    return render_template("link.html", report=report, ai_summary=ai_summary, ai_result=ai_result)