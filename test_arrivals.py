"""Pruebas de confirmación de llegadas firmadas con Ed25519."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import auth
import storage
import trips
from signatures import verificar_confirmacion


USUARIO = "viajero_prueba"
PASSWORD = "Contraseña ficticia 2026"

ETAPAS = [
    {
        "destino": "Aeropuerto de Berlín",
        "fecha": "2026-12-12",
        "hora": "12:30"
    }
]


@pytest.fixture
def entorno_llegadas(tmp_path, monkeypatch):
    """Prepara una cuenta y un itinerario aislados para cada prueba."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(trips, "TRIPS_FILE", tmp_path / "trips.json")

    auth.registrar_usuario(USUARIO, PASSWORD)

    clave = AESGCM.generate_key(bit_length=256)
    viaje_id = trips.crear_viaje(
        USUARIO, "Viaje a Berlín", ETAPAS, clave
    )

    return viaje_id, clave


def test_confirmar_llegada(entorno_llegadas):
    """Comprueba que el propietario puede firmar una llegada."""
    viaje_id, clave = entorno_llegadas

    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    viaje = trips.obtener_viaje(viaje_id, USUARIO, clave)
    confirmacion = viaje["etapas"][0]["confirmacion"]

    mensaje = confirmacion["mensaje"]
    firma = bytes.fromhex(confirmacion["firma"])

    cuenta = storage.buscar_usuario(USUARIO)
    publica = bytes.fromhex(cuenta["claves_firma"]["publica"])

    assert mensaje["viaje_id"] == viaje_id
    assert mensaje["etapa_indice"] == 0
    assert mensaje["propietario"] == USUARIO
    assert mensaje["etapa"] == ETAPAS[0]
    assert verificar_confirmacion(mensaje, firma, publica)


def test_rechazar_password_incorrecta(entorno_llegadas):
    """Comprueba que no se confirma una llegada con otra contraseña."""
    viaje_id, clave = entorno_llegadas

    with pytest.raises(ValueError, match="incorrectos"):
        trips.confirmar_llegada(
            viaje_id, USUARIO, 0, "Contraseña incorrecta", clave
        )

    viaje = trips.obtener_viaje(viaje_id, USUARIO, clave)
    assert "confirmacion" not in viaje["etapas"][0]


def test_contacto_no_puede_confirmar(entorno_llegadas):
    """Comprueba que un contacto no puede confirmar llegadas ajenas."""
    viaje_id, clave = entorno_llegadas

    auth.registrar_usuario("contacto", "Clave del contacto 2026")
    trips.compartir_viaje(viaje_id, USUARIO, "contacto", clave)

    with pytest.raises(ValueError, match="permiso"):
        trips.confirmar_llegada(
            viaje_id, "contacto", 0, "Clave del contacto 2026", clave
        )

    viaje = trips.obtener_viaje(viaje_id, USUARIO, clave)
    assert "confirmacion" not in viaje["etapas"][0]


def test_rechazar_confirmacion_duplicada(entorno_llegadas):
    """Comprueba que una etapa no puede confirmarse dos veces."""
    viaje_id, clave = entorno_llegadas

    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)
    original = trips.obtener_viaje(viaje_id, USUARIO, clave)
    confirmacion = original["etapas"][0]["confirmacion"]

    with pytest.raises(ValueError, match="ya tiene"):
        trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    viaje = trips.obtener_viaje(viaje_id, USUARIO, clave)
    assert viaje["etapas"][0]["confirmacion"] == confirmacion


def test_rechazar_etapa_invalida(entorno_llegadas):
    """Comprueba que solo pueden confirmarse etapas existentes."""
    viaje_id, clave = entorno_llegadas

    for indice in (-1, 1, True):
        with pytest.raises(ValueError, match="no existe"):
            trips.confirmar_llegada(
                viaje_id, USUARIO, indice, PASSWORD, clave
            )

    viaje = trips.obtener_viaje(viaje_id, USUARIO, clave)
    assert "confirmacion" not in viaje["etapas"][0]


