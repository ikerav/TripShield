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


def test_rechazar_etiqueta_manipulada():
    """Comprueba que alterar la etiqueta de autenticación se detecta."""
    clave = AESGCM.generate_key(bit_length=256)
    contexto = b"TripShield:prueba_de_etiqueta"
    itinerario = {"titulo": "Viaje de prueba", "etapas": []}
    datos = cifrar_itinerario(itinerario, clave, contexto)

    # AESGCM añade una etiqueta de 16 bytes al final del cifrado.
    contenido = bytearray.fromhex(datos["cifrado"])
    contenido[-1] ^= 1
    datos["cifrado"] = contenido.hex()

    with pytest.raises(InvalidTag):
        descifrar_itinerario(datos, clave, contexto)


def test_rechazar_clave_aes_incorrecta():
    """Comprueba que otra clave AES no permite recuperar los datos."""
    clave = AESGCM.generate_key(bit_length=256)
    contexto = b"TripShield:prueba_de_clave_incorrecta"
    itinerario = {"titulo": "Viaje de prueba", "etapas": []}
    datos = cifrar_itinerario(itinerario, clave, contexto)

    # Cambiamos un bit para obtener una clave distinta de la original.
    otra_clave = bytearray(clave)
    otra_clave[0] ^= 1

    with pytest.raises(InvalidTag):
        descifrar_itinerario(datos, bytes(otra_clave), contexto)


def test_nonces_de_96_bits_diferentes():
    """Comprueba el tamaño del nonce y dos cifrados independientes."""
    clave = AESGCM.generate_key(bit_length=256)
    contexto = b"TripShield:prueba_de_nonces"
    itinerario = {"titulo": "Viaje de prueba", "etapas": []}

    primero = cifrar_itinerario(itinerario, clave, contexto)
    segundo = cifrar_itinerario(itinerario, clave, contexto)

    nonce_primero = bytes.fromhex(primero["nonce"])
    nonce_segundo = bytes.fromhex(segundo["nonce"])

    assert len(nonce_primero) == 12
    assert len(nonce_segundo) == 12
    assert nonce_primero != nonce_segundo

    # Ambos resultados deben recuperar el mismo itinerario original.
    assert descifrar_itinerario(primero, clave, contexto) == itinerario
    assert descifrar_itinerario(segundo, clave, contexto) == itinerario