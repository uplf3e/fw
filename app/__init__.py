from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, routes
from .config import SECRET_KEY


def create_app() -> Flask:
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
    app.secret_key = SECRET_KEY
    db.init_db()
    routes.register(app)
    return app
