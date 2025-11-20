from threatkit import create_app

app = create_app()

app.config["UPLOAD_FOLDER"] = "/data/uploads"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
