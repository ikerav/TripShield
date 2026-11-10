"""Registro y autenticación con Scrypt y claves de firma por usuario."""

import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from signatures import (
    generar_claves_firma,
    proteger_clave_privada,
    desbloquear_clave_privada
)
from storage import (
    buscar_usuario,
    guardar_usuario,
    guardar_claves_firma_si_faltan
)


def crear_scrypt(salt: bytes) -> Scrypt:
    """Configura Scrypt para verificar las contraseñas almacenadas."""
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)


def hash_password(password: str) -> dict:
    """Genera un hash Scrypt con una sal aleatoria de 16 bytes."""
    salt = os.urandom(16)
    password_hash = crear_scrypt(salt).derive(password.encode("utf-8"))

    return {
        "salt": salt.hex(),
        "hash": password_hash.hex()
    }


def verify_password(password: str, stored_data: dict) -> bool:
    """Verifica una contraseña mediante el hash Scrypt almacenado."""
    salt = bytes.fromhex(stored_data["salt"])
    password_hash = bytes.fromhex(stored_data["hash"])

    try:
        crear_scrypt(salt).verify(password.encode("utf-8"), password_hash)
        return True
    except InvalidKey:
        return False


def _crear_registro_claves_firma(username: str, password: str) -> dict:
    """Prepara la clave pública y la privada cifrada de una cuenta."""
    privada, publica = generar_claves_firma()
    privada_protegida = proteger_clave_privada(privada, password, username)

    return {
        "publica": publica.hex(),
        "privada_protegida": privada_protegida
    }


def registrar_usuario(username: str, password: str) -> None:
    """Registra una cuenta con contraseña protegida y claves Ed25519."""
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("El usuario y la contraseña deben ser texto.")

    username = username.strip()
    if not 3 <= len(username) <= 30:
        raise ValueError("El usuario debe tener entre 3 y 30 caracteres.")

    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")

    datos = hash_password(password)
    datos["claves_firma"] = _crear_registro_claves_firma(username, password)
    guardar_usuario(username, datos)


def autenticar_usuario(username: str, password: str) -> bool:
    """Autentica la cuenta y añade claves de firma si todavía no existen."""
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    username = username.strip()
    if not username or not password:
        return False

    usuario = buscar_usuario(username)
    if usuario is None or not verify_password(password, usuario):
        return False

    # Las cuentas antiguas reciben claves solo tras verificar su contraseña.
    if "claves_firma" not in usuario:
        claves = _crear_registro_claves_firma(username, password)
        guardar_claves_firma_si_faltan(username, claves)

    return True


def obtener_clave_firma_usuario(username: str, password: str) -> bytes:
    """Autentica la cuenta y desbloquea su clave privada para firmar."""
    if not autenticar_usuario(username, password):
        raise ValueError("Usuario o contraseña incorrectos.")

    username = username.strip()
    usuario = buscar_usuario(username)

    # Recuperamos la privada cifrada de la cuenta que acabamos de autenticar.
    try:
        protegida = usuario["claves_firma"]["privada_protegida"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "La cuenta no tiene un registro de firma válido."
        ) from error

    return desbloquear_clave_privada(protegida, password, username)