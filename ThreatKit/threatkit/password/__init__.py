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

    @app.get("/")
    def _root():
        from flask import render_template
        return render_template("index.html") 

    return app
