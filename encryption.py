"""Cifrado autenticado de itinerarios mediante AES-256-GCM."""

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def cifrar_itinerario(
    itinerario: dict, clave: bytes, contexto: bytes
) -> dict:
    """Cifra un itinerario con AES-256-GCM y autentica su contexto."""
    if len(clave) != 32:
        raise ValueError("La clave AES debe tener 32 bytes (256 bits).")

    datos = json.dumps(
        itinerario, ensure_ascii=False, sort_keys=True
    ).encode("utf-8")

    # Nonce aleatorio de 96 bits; no debe reutilizarse con la misma clave.
    nonce = os.urandom(12)

    # AESGCM incorpora una etiqueta de autenticación de 128 bits.
    cifrado = AESGCM(clave).encrypt(nonce, datos, contexto)

    return {
        "nonce": nonce.hex(),
        "cifrado": cifrado.hex()
    }


def descifrar_itinerario(
    datos_cifrados: dict, clave: bytes, contexto: bytes
) -> dict:
    """Descifra un itinerario y comprueba su integridad y su contexto."""
    if len(clave) != 32:
        raise ValueError("La clave AES debe tener 32 bytes (256 bits).")

    # Recuperamos los bytes del nonce y del cifrado guardados en hexadecimal.
    nonce = bytes.fromhex(datos_cifrados["nonce"])
    cifrado = bytes.fromhex(datos_cifrados["cifrado"])

    if len(nonce) != 12:
        raise ValueError("El nonce debe tener 12 bytes (96 bits).")

    # Si la autenticación falla, decrypt lanza InvalidTag y rechaza los datos.
    datos = AESGCM(clave).decrypt(nonce, cifrado, contexto)

    return json.loads(datos.decode("utf-8"))