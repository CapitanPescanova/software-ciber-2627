"""Módulo 1 · Identidad y secretos: servicio HTTP (contrato v1.0.2). Base compartida (Omar).

Cada endpoint vive en su propio fichero (Blueprint) para que cada persona edite el suyo:
  auth_register.py -> POST /auth/register (AAA-18, Jaime)
  auth_login.py    -> POST /auth/login    (AAA-3, Diego)
  security.py      -> hash y token        (AAA-19, Omar)
GET /auth/validate (AAA-20) y GET /secrets/{clave} llegan en el Sprint 2.
"""
import os

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

import database
import security
from auth_login import login_bp
from auth_register import register_bp


def create_app(config=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "identidad.db")
    if config:
        app.config.update(config)
    database.init_app(app)

    app.register_blueprint(register_bp)
    app.register_blueprint(login_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok", module="01-identidad")

    @app.errorhandler(security.ConfigError)
    def config_error(_e):
        return jsonify(error="Error de configuración del servidor"), 500

    @app.errorhandler(HTTPException)
    def http_error(e):
        return jsonify(error=e.description), e.code

    @app.errorhandler(Exception)
    def unexpected_error(_e):
        return jsonify(error="Error no esperado"), 500

    return app


# Instancia que usa gunicorn en el contenedor: `gunicorn app:app`.
# /health funciona aunque falte JWT_SECRET, para que el CI del monorepo no falle.
app = create_app()
