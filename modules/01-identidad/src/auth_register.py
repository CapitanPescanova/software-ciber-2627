"""POST /auth/register (AAA-18). Fichero de Jaime."""
import re
import sqlite3

from flask import Blueprint, jsonify, request

import database
import security

register_bp = Blueprint("register", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DEFAULT_ROLE = "analista"


def validar_registro(data):
    """Devuelve un mensaje de error o None si los datos son válidos."""
    if not isinstance(data, dict):
        return "El cuerpo debe ser un JSON con username, email y password"
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    if not all(isinstance(v, str) and v for v in (username, password, email)):
        return "Faltan campos obligatorios: username, email y password"
    if not 3 <= len(username) <= 50:
        return "El username debe tener entre 3 y 50 caracteres"
    if not 8 <= len(password) <= 128:
        return "La contraseña debe tener entre 8 y 128 caracteres"
    if not EMAIL_RE.match(email):
        return "El email no tiene un formato válido"
    return None


@register_bp.post("/auth/register")
def register():
    security.get_secret()  # falla antes de tocar la base de datos si falta JWT_SECRET
    data = request.get_json(silent=True)
    error = validar_registro(data)
    if error:
        return jsonify(error=error), 400

    db = database.get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (
                data["username"],
                data["email"].lower(),
                security.hash_password(data["password"]),
                DEFAULT_ROLE,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="El usuario o el email ya existen"), 409

    row = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    token = security.crear_token(row["username"], row["role"])
    return jsonify(token=token, user=database.usuario_publico(row)), 201
