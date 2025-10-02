from threatkit import create_app
import os
from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename

app = create_app()
app.secret_key = "your-secret-key"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"exe", "pdf", "zip", "docx", "xlsx", "txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))

    file = request.files["file"]

    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        flash(f"File '{filename}' uploaded successfully.")
        return redirect(url_for("index"))
    else:
        flash("Invalid file type.")
        return redirect(url_for("index"))
    
@app.route("/")
def index():
    return render_template("malware_checker.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
