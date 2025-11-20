from flask import Blueprint

bp = Blueprint("link", __name__)

from threatkit.url_scanner import routes
