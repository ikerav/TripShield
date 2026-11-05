"""Autenticación de usuarios mediante Scrypt.
Generación y verificación segura de hashes de contraseñas"""

import os

import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def crear_scrypt(salt: bytes) -> Scrypt:
    """configura Scrypt con una salida de 256 bits (32 bytes)
    y parámetros de coste definidos."""

    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)


def hash_password(password: str) -> dict:
    """Genera un hash Scrypt usando una sal aleatoria de 
    128 bits (16 bytes)"""

    salt = os.urandom(16)
    password_hash = crear_scrypt(salt).derive(password.encode("utf-8"))

    return {
        "salt": salt.hex(),
        "hash": password_hash.hex()
        }


def verify_password(password: str, stored_data: dict) -> bool:
    """verifica una contraseña utilizando el hash y la sal almacenados."""

    salt = bytes.fromhex(stored_data["salt"])
    password_hash = bytes.fromhex(stored_data["hash"])

    try:
        crear_scrypt(salt).verify(password.encode("utf-8"), password_hash)
        return True
    except InvalidKey:
        return False