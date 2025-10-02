from flask import Flask
from .malware.routes import bp as malware_bp  # notice the dot
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = "supersecretkey"

    # Configuration
    app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
    
    # Blueprints
    from .main.routes import bp as main_bp
    from .password.routes import bp as password_bp
    from .malware.routes import bp as malware_bp
    from .emailcheck.routes import bp as email_bp
    from .linkcheck.routes import bp as link_bp

    app.register_blueprint(main_bp)                
    app.register_blueprint(password_bp, url_prefix="/password")
    app.register_blueprint(malware_bp,  url_prefix="/malware")
    app.register_blueprint(email_bp,    url_prefix="/email")
    app.register_blueprint(link_bp,     url_prefix="/link")

    return app
