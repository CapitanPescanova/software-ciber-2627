"""Utilidades compartidas por todos los tests del módulo 1."""
import os
import secrets
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Al importar app se crea la instancia que usa gunicorn; que no deje un .db en la carpeta del repo.
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "identidad_import_tests.db"))

import app as app_module  # noqa: E402

USUARIO = {
    "username": "usuario.ejemplo",
    "email": "usuario.ejemplo@ciberurjc.local",
    "password": "contrasena-de-ejemplo",
}


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        # Clave aleatoria generada en cada ejecución: no hay secretos escritos en el código.
        self.jwt_secret = secrets.token_hex(16)
        os.environ["JWT_SECRET"] = self.jwt_secret
        self.app = app_module.create_app({"DB_PATH": self.db_path, "TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("JWT_SECRET", None)
        self.tmp.cleanup()

    def registrar(self, **cambios):
        return self.client.post("/auth/register", json={**USUARIO, **cambios})

    def login(self, **cuerpo):
        return self.client.post("/auth/login", json=cuerpo)

    def contar_usuarios(self):
        return sqlite3.connect(self.db_path).execute("SELECT COUNT(*) FROM users").fetchone()[0]
