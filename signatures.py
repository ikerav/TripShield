"""Gestión de claves Ed25519 y firmas de llegada de TripShield."""

import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys import derivar_clave_proteccion


SIGNING_KEY_CONTEXT = b"TripShield:clave-firma:v1:"
SIGNATURE_CONTEXT = b"TripShield:llegada:v1:"


def generar_claves_firma() -> tuple[bytes, bytes]:
    """Devuelve las claves Ed25519 en orden: privada y pública."""
    privada = Ed25519PrivateKey.generate()

    # La pública se obtiene a partir de su clave privada correspondiente.
    publica = privada.public_key()

    return privada.private_bytes_raw(), publica.public_bytes_raw()


def proteger_clave_privada(
    privada: bytes, password: str, usuario: str
) -> dict:
    """Cifra la clave privada Ed25519 y la vincula a su usuario."""
    if len(privada) != 32:
        raise ValueError("La clave privada Ed25519 debe tener 32 bytes.")

    if not usuario:
        raise ValueError("Debes indicar el usuario propietario de la clave.")

    # Sal de 128 bits, independiente de la usada para verificar la contraseña.
    salt = os.urandom(16)
    clave_proteccion = derivar_clave_proteccion(password, salt)

    # Nonce de 96 bits para cifrar la clave privada mediante AES-GCM.
    nonce = os.urandom(12)

    # El contexto autentica la cuenta a la que pertenece la clave privada.
    contexto = SIGNING_KEY_CONTEXT + usuario.encode("utf-8")
    cifrado = AESGCM(clave_proteccion).encrypt(nonce, privada, contexto)

    return {
        "version": 1,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "cifrado": cifrado.hex()
    }


def desbloquear_clave_privada(
    datos: dict, password: str, usuario: str
) -> bytes:
    """Recupera la clave privada y verifica su vinculación con el usuario."""
    if not usuario:
        raise ValueError("Debes indicar el usuario propietario de la clave.")

    if not isinstance(datos, dict) or datos.get("version") != 1:
        raise ValueError("Formato o versión de clave de firma no compatible.")

    # Recuperamos los campos y comprobamos que contienen texto hexadecimal.
    try:
        salt = bytes.fromhex(datos["salt"])
        nonce = bytes.fromhex(datos["nonce"])
        cifrado = bytes.fromhex(datos["cifrado"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            "El registro de la clave privada tiene campos inválidos."
        ) from error

    # El cifrado incluye 32 bytes de clave privada y 16 bytes de etiqueta GCM.
    if len(salt) != 16 or len(nonce) != 12 or len(cifrado) != 48:
        raise ValueError(
            "El registro de la clave privada tiene longitudes inválidas."
        )

    clave_proteccion = derivar_clave_proteccion(password, salt)
    contexto = SIGNING_KEY_CONTEXT + usuario.encode("utf-8")

    # Una contraseña incorrecta o un registro manipulado provocan InvalidTag.
    return AESGCM(clave_proteccion).decrypt(nonce, cifrado, contexto)


def _serializar_confirmacion(confirmacion: dict) -> bytes:
    """Produce una representación estable y específica de una llegada."""
    if not isinstance(confirmacion, dict):
        raise ValueError("La confirmación debe ser un diccionario.")

    # Usamos un formato JSON fijo para que el mismo mensaje genere los mismos bytes.
    datos = json.dumps(
        confirmacion,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")

    return SIGNATURE_CONTEXT + datos


def firmar_confirmacion(confirmacion: dict, privada: bytes) -> bytes:
    """Firma una declaración de llegada utilizando Ed25519."""
    clave = Ed25519PrivateKey.from_private_bytes(privada)
    mensaje = _serializar_confirmacion(confirmacion)
    return clave.sign(mensaje)


def verificar_confirmacion(
    confirmacion: dict, firma: bytes, publica: bytes
) -> bool:
    """Comprueba que la firma corresponde al mensaje y a la clave pública."""
    try:
        clave = Ed25519PublicKey.from_public_bytes(publica)
        mensaje = _serializar_confirmacion(confirmacion)
        clave.verify(firma, mensaje)
    except (InvalidSignature, TypeError, ValueError):
        # Una firma incorrecta o datos mal formados se rechazan.
        return False

    return True