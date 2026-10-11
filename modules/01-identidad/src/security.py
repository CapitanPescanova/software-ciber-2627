"""Contraseñas y tokens del módulo 1 (AAA-19, AAA-18 y AAA-3)."""
import os
import time

import jwt
from werkzeug.security import check_password_hash, generate_password_hash

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 30 * 60  # 30 minutos, como dice el contrato

# Hash de relleno: se usa cuando el usuario no existe para que el login tarde
# parecido exista o no la cuenta (evita enumerar usuarios por tiempo de respuesta).
_DUMMY_HASH = generate_password_hash("contrasena-de-relleno", method="pbkdf2:sha256")


class ConfigError(RuntimeError):
    """Falta configuración obligatoria (por ejemplo, JWT_SECRET)."""


def get_secret():
    """Lee la clave de firma del entorno. Nunca está escrita en el código."""
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ConfigError("La variable de entorno JWT_SECRET no está definida")
    return secret


def hash_password(password):
    """Hash con sal (scrypt por defecto en Werkzeug 3). Nunca se guarda en claro."""
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)


def verify_dummy(password):
    """Comprobación de relleno cuando el usuario no existe."""
    check_password_hash(_DUMMY_HASH, password)


def crear_token(username, role, now=None):
    """JWT HS256 con sub, role, iat y exp (iat + 30 min). Sin datos sensibles."""
    iat = int(now if now is not None else time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": iat,
        "exp": iat + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, get_secret(), algorithm=ALGORITHM)
