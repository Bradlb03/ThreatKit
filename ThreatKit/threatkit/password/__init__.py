# threatkit/__init__.py
from flask import Flask
from pathlib import Path

def create_app():
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent / "static")  # optional
    )

    # Register blueprints
    from .password_.routes import bp as password_bp
    app.register_blueprint(password_bp)

    # You can register other toolkits here too:
    # from .emailcheck.routes import email_bp; app.register_blueprint(email_bp)
    # from .url_scanner.routes import url_bp; app.register_blueprint(url_bp)
    # from .malware.routes import malware_bp; app.register_blueprint(malware_bp)

    # Home route (optional): redirect to index or password page
    @app.get("/")
    def _root():
        from flask import render_template
        return render_template("index.html")  # you already have index.html

    return app
