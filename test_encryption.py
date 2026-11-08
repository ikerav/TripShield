"""Pruebas del cifrado y la autenticación de itinerarios."""

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encryption import cifrar_itinerario, descifrar_itinerario


def test_cifrar_y_descifrar_itinerario():
    """Comprueba que se recuperan exactamente los datos originales."""
    clave = AESGCM.generate_key(bit_length=256)
    contexto = b"TripShield:viaje_de_prueba"
    itinerario = {
        "titulo": "Viaje a Berlín",
        "etapas": [
            {"destino": "Aeropuerto", "hora_prevista": "12:30"}
        ]
    }

    datos_cifrados = cifrar_itinerario(itinerario, clave, contexto)
    recuperado = descifrar_itinerario(datos_cifrados, clave, contexto)

    assert recuperado == itinerario


def test_rechazar_cifrado_manipulado():
    """Comprueba que modificar el cifrado provoca su rechazo."""
    clave = AESGCM.generate_key(bit_length=256)
    contexto = b"TripShield:viaje_de_prueba"
    itinerario = {"titulo": "Viaje a Berlín", "etapas": []}

    datos_cifrados = cifrar_itinerario(itinerario, clave, contexto)

    # Alteramos un bit del cifrado para simular una manipulación.
    manipulados = datos_cifrados.copy()
    contenido = bytearray.fromhex(manipulados["cifrado"])
    contenido[0] ^= 1
    manipulados["cifrado"] = contenido.hex()

    # La prueba exige que el descifrado lance este error de autenticación.
    with pytest.raises(InvalidTag):
        descifrar_itinerario(manipulados, clave, contexto)