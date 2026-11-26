"""Registro, autenticación y claves de firma certificadas de TripShield."""

import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pki import emitir_certificado_usuario, validar_certificado_usuario
from signatures import (
    generar_claves_firma,
    proteger_clave_privada,
    desbloquear_clave_privada
)
from storage import (
    buscar_usuario,
    guardar_usuario,
    guardar_claves_firma_si_faltan,
    guardar_certificado_si_falta
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
    try:
        salt = bytes.fromhex(stored_data["salt"])
        password_hash = bytes.fromhex(stored_data["hash"])

        crear_scrypt(salt).verify(password.encode("utf-8"), password_hash)
        return True

    except (InvalidKey, KeyError, TypeError, ValueError):
        return False


def _buscar_cuenta_autenticada(username: str, password: str) -> dict | None:
    """Busca la cuenta solo si su nombre y contraseña permiten autenticarla."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    username = username.strip()
    if not username or not password:
        return None

    cuenta = buscar_usuario(username)
    if cuenta is None or not verify_password(password, cuenta):
        return None
    return cuenta


def verificar_credenciales(username: str, password: str) -> bool:
    """Comprueba las credenciales para autorizar una operación sensible."""
    return _buscar_cuenta_autenticada(username, password) is not None


def _crear_registro_claves_firma(
    username: str, password: str, password_ca: str
) -> dict:
    """Prepara el par protegido y su certificado antes de guardar la cuenta."""
    privada, publica = generar_claves_firma()
    protegida = proteger_clave_privada(privada, password, username)
    certificado = emitir_certificado_usuario(username, publica, password_ca)
    return {
        "publica": publica.hex(),
        "privada_protegida": protegida,
        "certificado": certificado
    }


def _desbloquear_claves_usuario(
    username: str, password: str, claves: dict
) -> tuple[bytes, bytes]:
    """Recupera la privada y comprueba que corresponde a la pública almacenada."""
    if not isinstance(claves, dict):
        raise ValueError("La cuenta no tiene un registro de firma válido.")
    try:
        publica = bytes.fromhex(claves["publica"])
        privada = desbloquear_clave_privada(
            claves["privada_protegida"], password, username
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("La cuenta tiene datos de firma inválidos.") from error

    derivada = Ed25519PrivateKey.from_private_bytes(privada).public_key()
    if publica != derivada.public_bytes_raw():
        raise ValueError("Las claves pública y privada de la cuenta no coinciden.")
    return privada, publica


def _validar_claves_certificadas(username: str, claves: dict) -> bytes:
    """Valida la identidad y la pública certificada de la cuenta."""
    if not isinstance(claves, dict):
        raise ValueError("La cuenta no tiene un registro de firma válido.")
    try:
        publica = bytes.fromhex(claves["publica"])
        certificada = validar_certificado_usuario(claves["certificado"], username)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("No se puede validar el certificado de la cuenta.") from error

    if publica != certificada:
        raise ValueError("La pública almacenada no coincide con su certificado.")
    return certificada


def registrar_usuario(username: str, password: str, password_ca: str) -> None:
    """Registra una cuenta con contraseña protegida y claves certificadas."""
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("El usuario y la contraseña deben ser texto.")

    username = username.strip()
    if not 3 <= len(username) <= 30:
        raise ValueError("El usuario debe tener entre 3 y 30 caracteres.")
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    if buscar_usuario(username) is not None:
        raise ValueError("El nombre de usuario ya existe.")

    datos = hash_password(password)
    datos["claves_firma"] = _crear_registro_claves_firma(
        username, password, password_ca
    )

    # Un fallo al emitir el certificado impide guardar una cuenta incompleta.
    guardar_usuario(username, datos)


def autenticar_usuario(
    username: str, password: str, password_ca: str
) -> bool:
    """Autentica y certifica las cuentas antiguas conservando sus claves."""
    cuenta = _buscar_cuenta_autenticada(username, password)
    if cuenta is None:
        return False
    username = username.strip()

    if "claves_firma" not in cuenta:
        nuevas = _crear_registro_claves_firma(username, password, password_ca)
        claves = guardar_claves_firma_si_faltan(username, nuevas)
    else:
        claves = cuenta["claves_firma"]

    if not isinstance(claves, dict):
        raise ValueError("La cuenta no tiene un registro de firma válido.")

    if "certificado" not in claves:
        # Antes de certificar una pública antigua, comprobamos su privada.
        _, publica = _desbloquear_claves_usuario(username, password, claves)
        certificado = emitir_certificado_usuario(username, publica, password_ca)
        guardado = guardar_certificado_si_falta(
            username, certificado, claves["publica"]
        )
        claves = {**claves, "certificado": guardado}

    _validar_claves_certificadas(username, claves)
    return True


def obtener_clave_firma_usuario(username: str, password: str) -> bytes:
    """Desbloquea la privada del usuario solo si sus claves están certificadas."""
    cuenta = _buscar_cuenta_autenticada(username, password)
    if cuenta is None:
        raise ValueError("Usuario o contraseña incorrectos.")

    username = username.strip()
    claves = cuenta.get("claves_firma")
    _validar_claves_certificadas(username, claves)
    privada, _ = _desbloquear_claves_usuario(username, password, claves)
    return privada


def obtener_publica_firma_usuario(username: str) -> bytes:
    """Recupera la pública certificada sin desbloquear ninguna privada."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Debes indicar un usuario válido.")

    username = username.strip()
    cuenta = buscar_usuario(username)
    if cuenta is None:
        raise ValueError("El usuario debe estar registrado.")

    return _validar_claves_certificadas(
        username, cuenta.get("claves_firma")
    )