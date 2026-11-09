"""Pruebas de almacenamiento, cifrado y acceso a itinerarios."""

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import trips


ETAPAS_PRUEBA = [
    {"destino": "Aeropuerto de Berlín", "fecha": "2026-12-12", "hora": "12:30"},
    {"destino": "Hotel Alexanderplatz", "fecha": "2026-12-12", "hora": "15:00"}
]


@pytest.fixture
def entorno_viajes(tmp_path, monkeypatch):
    """Prepara un almacenamiento temporal y una clave AES de prueba."""
    # Evitamos modificar los viajes reales durante las pruebas.
    monkeypatch.setattr(trips, "TRIPS_FILE", tmp_path / "trips.json")

    return AESGCM.generate_key(bit_length=256)


def test_crear_y_recuperar_viaje(entorno_viajes):
    """Comprueba que se puede crear y recuperar un viaje cifrado."""
    clave = entorno_viajes

    viaje_id = trips.crear_viaje(
        "viajero", "Viaje a Berlín", ETAPAS_PRUEBA, clave
    )

    viaje = trips.obtener_viaje(viaje_id, "viajero", clave)

    assert viaje["id"] == viaje_id
    assert viaje["propietario"] == "viajero"
    assert viaje["titulo"] == "Viaje a Berlín"
    assert viaje["etapas"] == ETAPAS_PRUEBA


def test_rechazar_usuario_no_autorizado(entorno_viajes):
    """Comprueba que un usuario ajeno no puede consultar el viaje."""
    clave = entorno_viajes

    viaje_id = trips.crear_viaje(
        "viajero", "Viaje a Berlín", ETAPAS_PRUEBA, clave
    )

    assert trips.obtener_viaje(viaje_id, "intruso", clave) is None
    assert trips.listar_viajes("intruso", clave) == []


def test_almacenamiento_cifrado(entorno_viajes):
    """Comprueba que los datos privados no se guardan en claro."""
    clave = entorno_viajes

    viaje_id = trips.crear_viaje(
        "viajero", "Viaje a Berlín", ETAPAS_PRUEBA, clave
    )

    contenido = trips.TRIPS_FILE.read_text(encoding="utf-8")
    registro = trips.cargar_viajes()[viaje_id]

    assert "Viaje a Berlín" not in contenido
    assert "Aeropuerto de Berlín" not in contenido
    assert "Hotel Alexanderplatz" not in contenido
    assert "nonce" in registro["datos_cifrados"]
    assert "cifrado" in registro["datos_cifrados"]


def test_rechazar_viaje_manipulado(entorno_viajes):
    """Comprueba que AES-GCM rechaza un itinerario modificado."""
    clave = entorno_viajes

    viaje_id = trips.crear_viaje(
        "viajero", "Viaje a Berlín", ETAPAS_PRUEBA, clave
    )

    viajes = trips.cargar_viajes()
    datos = viajes[viaje_id]["datos_cifrados"]

    # Modificamos un bit del contenido cifrado almacenado.
    contenido = bytearray.fromhex(datos["cifrado"])
    contenido[0] ^= 1
    datos["cifrado"] = contenido.hex()

    trips.guardar_viajes(viajes)

    # AES-GCM debe detectar la alteración y rechazar el descifrado.
    with pytest.raises(InvalidTag):
        trips.obtener_viaje(viaje_id, "viajero", clave)

