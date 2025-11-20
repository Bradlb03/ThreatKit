from flask import Flask
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = "supersecretkey"

    # Configuration
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    
    # Blueprints
    from .main.routes import bp as main_bp
    from .password.routes import bp as password_bp
    from .malware.routes import bp as malware_bp
    from .emailcheck.routes import bp as email_bp
    from .url_scanner.routes import bp as link_bp
    from .docs.routes import bp as docs_bp


    app.register_blueprint(main_bp)                
    app.register_blueprint(password_bp, url_prefix="/password")
    app.register_blueprint(malware_bp,  url_prefix="/malware")
    app.register_blueprint(email_bp,    url_prefix="/email")
    app.register_blueprint(link_bp,     url_prefix="/link")
    app.register_blueprint(docs_bp, url_prefix="/docs")


    return app
