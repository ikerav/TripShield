"""Generación y protección de la clave maestra de TripShield."""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MASTER_KEY_FILE = Path(__file__).resolve().parent / "data" / "master_key.json"
KEY_CONTEXT = b"TripShield:clave-maestra:v1"


def derivar_clave_proteccion(password: str, salt: bytes) -> bytes:
    """Deriva una clave de 256 bits para proteger la clave maestra."""
    if not password:
        raise ValueError("La contraseña de protección no puede estar vacía.")

    if len(salt) != 16:
        raise ValueError("La sal debe tener 16 bytes (128 bits).")

    # Scrypt añade coste de memoria y cálculo a los intentos de contraseña.
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)

    return kdf.derive(password.encode("utf-8"))


def crear_clave_maestra(password: str) -> None:
    """Genera y guarda una clave AES-256 cifrada, sin sobrescribirla."""
    if MASTER_KEY_FILE.exists():
        raise FileExistsError("La clave maestra ya existe.")

    if len(password) < 16:
        raise ValueError(
            "La contraseña de protección debe tener al menos 16 caracteres."
        )

    # Usamos una sal independiente para derivar la clave de protección.
    salt = os.urandom(16)
    clave_proteccion = derivar_clave_proteccion(password, salt)

    # Generamos una clave maestra de 256 bits y un nonce de 96 bits.
    clave_maestra = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    cifrado = AESGCM(clave_proteccion).encrypt(
        nonce, clave_maestra, KEY_CONTEXT
    )

    datos = {
        "version": 1,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "cifrado": cifrado.hex()
    }

    MASTER_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)

    # O_EXCL impide sobrescribir; 0o600 permite acceso solo al propietario
    # del archivo en sistemas Unix, como macOS y Linux.
    descriptor = os.open(
        MASTER_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(datos, file, indent=4)


def cargar_clave_maestra(password: str) -> bytes:
    """Recupera la clave maestra y verifica la autenticidad del archivo."""
    with open(MASTER_KEY_FILE, "r", encoding="utf-8") as file:
        datos = json.load(file)

    if not isinstance(datos, dict) or datos.get("version") != 1:
        raise ValueError("Formato o versión de clave maestra no compatible.")

    # Validamos los campos antes de realizar la operación criptográfica.
    try:
        salt = bytes.fromhex(datos["salt"])
        nonce = bytes.fromhex(datos["nonce"])
        cifrado = bytes.fromhex(datos["cifrado"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            "El archivo de clave maestra tiene campos inválidos."
        ) from error

    # El cifrado contiene 32 bytes de clave y 16 bytes de etiqueta GCM.
    if len(salt) != 16 or len(nonce) != 12 or len(cifrado) != 48:
        raise ValueError(
            "El archivo de clave maestra tiene longitudes inválidas."
        )

    clave_proteccion = derivar_clave_proteccion(password, salt)

    # Una contraseña incorrecta o una manipulación provocan InvalidTag.
    return AESGCM(clave_proteccion).decrypt(nonce, cifrado, KEY_CONTEXT)