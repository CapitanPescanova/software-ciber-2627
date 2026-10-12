"""POST /auth/login (AAA-3). Fichero de Diego."""
from flask import Blueprint, jsonify, request

import database
import security

login_bp = Blueprint("login", __name__)


@login_bp.post("/auth/login")
def login():
    security.get_secret()
    data = request.get_json(silent=True)
    username = data.get("username") if isinstance(data, dict) else None
    password = data.get("password") if isinstance(data, dict) else None
    if not (isinstance(username, str) and username and isinstance(password, str) and password):
        return jsonify(error="Falta el nombre de usuario o la contraseña"), 400

    row = database.get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        security.verify_dummy(password)
        return jsonify(error="Usuario o contraseña incorrectos"), 401
    if not security.verify_password(password, row["password_hash"]):
        return jsonify(error="Usuario o contraseña incorrectos"), 401

    token = security.crear_token(row["username"], row["role"])
    return jsonify(token=token, user=database.usuario_publico(row)), 200
