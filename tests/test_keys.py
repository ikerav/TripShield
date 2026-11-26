"""Pruebas de creación y recuperación de la clave maestra."""

import pytest

from cryptography.exceptions import InvalidTag

import keys
from encryption import cifrar_itinerario, descifrar_itinerario
import json


def test_crear_y_recuperar_clave_maestra(tmp_path, monkeypatch):
    """Comprueba que la clave guardada permite recuperar un itinerario."""
    # Utilizamos un archivo temporal para no afectar a la clave real.
    monkeypatch.setattr(
        keys, "MASTER_KEY_FILE", tmp_path / "master_key.json"
    )
    password = "Frase ficticia para pruebas 2026"

    keys.crear_clave_maestra(password)
    clave = keys.cargar_clave_maestra(password)

    itinerario = {"titulo": "Viaje a Berlín", "etapas": []}
    contexto = b"TripShield:prueba_de_clave"
    cifrado = cifrar_itinerario(itinerario, clave, contexto)

    # Leemos otra vez el archivo para comprobar que recuperamos la misma clave.
    recargada = keys.cargar_clave_maestra(password)

    assert len(clave) == 32
    assert recargada == clave
    assert descifrar_itinerario(cifrado, recargada, contexto) == itinerario


def test_rechazar_password_de_proteccion_incorrecta(tmp_path, monkeypatch):
    """Comprueba que una contraseña incorrecta no desbloquea la clave."""
    monkeypatch.setattr(
        keys, "MASTER_KEY_FILE", tmp_path / "master_key.json"
    )
    keys.crear_clave_maestra("Frase ficticia para pruebas 2026")

    with pytest.raises(InvalidTag):
        keys.cargar_clave_maestra("Otra contraseña ficticia incorrecta")


def test_rechazar_clave_maestra_manipulada(tmp_path, monkeypatch):
    """Comprueba que una alteración de la clave maestra cifrada se detecta."""
    monkeypatch.setattr(
        keys, "MASTER_KEY_FILE", tmp_path / "master_key.json"
    )
    password = "Frase ficticia para pruebas 2026"
    keys.crear_clave_maestra(password)

    datos = json.loads(keys.MASTER_KEY_FILE.read_text(encoding="utf-8"))

    # Alteramos un bit del cifrado de la clave maestra.
    cifrado = bytearray.fromhex(datos["cifrado"])
    cifrado[0] ^= 1
    datos["cifrado"] = cifrado.hex()

    keys.MASTER_KEY_FILE.write_text(
        json.dumps(datos), encoding="utf-8"
    )

    with pytest.raises(InvalidTag):
        keys.cargar_clave_maestra(password)


def test_clave_maestra_existente_no_se_sobrescribe(tmp_path, monkeypatch):
    """Comprueba que generar otra clave no sustituye la original."""
    monkeypatch.setattr(
        keys, "MASTER_KEY_FILE", tmp_path / "master_key.json"
    )
    password = "Frase ficticia para pruebas 2026"
    keys.crear_clave_maestra(password)

    original = keys.MASTER_KEY_FILE.read_bytes()

    with pytest.raises(FileExistsError):
        keys.crear_clave_maestra(password)

    assert keys.MASTER_KEY_FILE.read_bytes() == original