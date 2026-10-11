"""Acceso a SQLite (librería estándar sqlite3) del módulo 1. Base compartida (Omar)."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analista'
);
"""


def get_db():
    """Devuelve la conexión de la petición actual (se crea la primera vez)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app):
    """Registra el cierre de conexión y crea las tablas si no existen."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        get_db().executescript(SCHEMA)


def usuario_publico(row):
    """Datos del usuario que pueden salir en una respuesta (nunca el hash)."""
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
    }
