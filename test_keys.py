"""Pruebas de creación y recuperación de la clave maestra."""

import pytest

from cryptography.exceptions import InvalidTag

import keys
from encryption import cifrar_itinerario, descifrar_itinerario


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