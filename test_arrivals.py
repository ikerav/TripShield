"""Pruebas de confirmación de llegadas firmadas con Ed25519."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import auth
import pki
import storage
import trips
from signatures import verificar_confirmacion
from encryption import cifrar_itinerario, descifrar_itinerario


PASSWORD_CA_PRUEBA = "Contraseña ficticia de CA para pruebas 2026!"
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
    """Aísla una CA, una cuenta y un itinerario para cada prueba."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(pki, "CA_DIRECTORY", tmp_path / "pki")
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    monkeypatch.setattr(trips, "TRIPS_FILE", tmp_path / "trips.json")

    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA_PRUEBA)

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

    auth.registrar_usuario(
        "contacto", "Clave del contacto 2026", PASSWORD_CA_PRUEBA
    )
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


def test_verificar_llegada_pendiente(entorno_llegadas):
    """Comprueba que una etapa sin confirmación devuelve None."""
    viaje_id, clave = entorno_llegadas

    assert trips.verificar_llegada(
        viaje_id, USUARIO, 0, clave
    ) is None


def test_verificar_llegada_compartida(entorno_llegadas):
    """Comprueba que el propietario y su contacto verifican la llegada."""
    viaje_id, clave = entorno_llegadas

    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    assert trips.verificar_llegada(
        viaje_id, USUARIO, 0, clave
    ) is True

    auth.registrar_usuario(
        "contacto", "Clave del contacto 2026", PASSWORD_CA_PRUEBA
    )
    trips.compartir_viaje(viaje_id, USUARIO, "contacto", clave)

    assert trips.verificar_llegada(
        viaje_id, "contacto", 0, clave
    ) is True


def test_verificacion_rechaza_usuario_ajeno(entorno_llegadas):
    """Comprueba que un usuario ajeno no puede consultar la confirmación."""
    viaje_id, clave = entorno_llegadas

    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    with pytest.raises(ValueError, match="acceso"):
        trips.verificar_llegada(
            viaje_id, "intruso", 0, clave
        )


def test_rechazar_llegada_con_etapa_modificada(entorno_llegadas):
    """Comprueba que una firma no valida una etapa con datos diferentes."""
    viaje_id, clave = entorno_llegadas

    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    viajes = trips.cargar_viajes()
    viaje = viajes[viaje_id]

    contexto = trips._contexto_viaje(
        viaje_id, viaje["propietario"], viaje["contacto"]
    )
    itinerario = descifrar_itinerario(
        viaje["datos_cifrados"], clave, contexto
    )

    # Modificamos el destino conservando la declaración y su firma originales.
    itinerario["etapas"][0]["destino"] = "Otro destino"
    viaje["datos_cifrados"] = cifrar_itinerario(
        itinerario, clave, contexto
    )
    trips.guardar_viajes(viajes)

    assert trips.verificar_llegada(viaje_id, USUARIO, 0, clave) is False


@pytest.mark.parametrize("destino", ["otro_viaje", "otra_etapa"])
def test_rechazar_confirmacion_reutilizada(entorno_llegadas, destino):
    """Una firma válida no debe aceptar otra etapa u otro viaje."""
    viaje_id, clave = entorno_llegadas
    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    original = trips.obtener_viaje(viaje_id, USUARIO, clave)
    confirmacion = original["etapas"][0]["confirmacion"]

    # Usamos los mismos datos para aislar el ID del viaje o el índice de etapa.
    destino_id = viaje_id
    indice = 1 if destino == "otra_etapa" else 0

    if destino == "otro_viaje":
        destino_id = trips.crear_viaje(
            USUARIO, "Otro viaje de prueba", ETAPAS, clave
        )

    viajes = trips.cargar_viajes()
    registro = viajes[destino_id]
    contexto = trips._contexto_viaje(
        destino_id, USUARIO, registro["contacto"]
    )
    itinerario = descifrar_itinerario(
        registro["datos_cifrados"], clave, contexto
    )

    if destino == "otra_etapa":
        itinerario["etapas"].append(dict(ETAPAS[0]))

    itinerario["etapas"][indice]["confirmacion"] = confirmacion

    # Reciframos para que AES-GCM sea válido y se compruebe la firma interna.
    registro["datos_cifrados"] = cifrar_itinerario(
        itinerario, clave, contexto
    )
    trips.guardar_viajes(viajes)

    # La firma original sigue siendo correcta, pero no pertenece al destino.
    publica = auth.obtener_publica_firma_usuario(USUARIO)
    assert verificar_confirmacion(
        confirmacion["mensaje"],
        bytes.fromhex(confirmacion["firma"]),
        publica
    )

    assert trips.verificar_llegada(
        destino_id, USUARIO, indice, clave
    ) is False

    assert trips.verificar_llegada(
        viaje_id, USUARIO, 0, clave
    ) is True


def test_rechazar_firma_de_llegada_manipulada(entorno_llegadas):
    """Comprueba que la aplicación rechaza una firma alterada."""
    viaje_id, clave = entorno_llegadas
    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    viajes = trips.cargar_viajes()
    registro = viajes[viaje_id]
    contexto = trips._contexto_viaje(
        viaje_id, USUARIO, registro["contacto"]
    )
    itinerario = descifrar_itinerario(
        registro["datos_cifrados"], clave, contexto
    )

    confirmacion = itinerario["etapas"][0]["confirmacion"]

    # Alteramos un bit de la firma conservando el mensaje original.
    firma = bytearray.fromhex(confirmacion["firma"])
    firma[0] ^= 1
    confirmacion["firma"] = firma.hex()

    # Mantenemos válido el cifrado para aislar el rechazo de la firma.
    registro["datos_cifrados"] = cifrar_itinerario(
        itinerario, clave, contexto
    )
    trips.guardar_viajes(viajes)

    assert trips.verificar_llegada(
        viaje_id, USUARIO, 0, clave
    ) is False