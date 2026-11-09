"""Gestión y almacenamiento de itinerarios cifrados de TripShield"""

import json
from pathlib import Path
from uuid import uuid4

from encryption import cifrar_itinerario, descifrar_itinerario


TRIPS_FILE = Path(__file__).resolve().parent / "data" / "trips.json"

def _contexto_viaje(viaje_id: str, propietario: str) -> bytes:
    """Construye el AAD que vincula cada viaje con su propietario."""
    return f"TripShield:viaje:{viaje_id}:{propietario}".encode("utf-8")


def cargar_viajes() -> dict:
    """Recupera los viajes almacenados cifrados en el archivo JSON"""
    if not TRIPS_FILE.exists():
        return {}

    with open(TRIPS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def guardar_viajes(viajes: dict) -> None:
    """almacena los registros de viajes en un archivo JSON"""
    TRIPS_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Guardamos primero en un archivo temporal para evitar escrituras incompletas.
    temporal = TRIPS_FILE.with_suffix(".tmp")

    with open(temporal, "w", encoding="utf-8") as file:
        json.dump(viajes, file, indent=4, ensure_ascii=False)

    temporal.replace(TRIPS_FILE)


def crear_viaje(
    propietario: str, titulo: str, etapas: list[dict], clave: bytes
    ) -> str:
    """Crea un viaje y almacena su itinerario cifrado"""
    # Validación
    if not propietario or not titulo.strip() or not etapas:
        raise ValueError("El viaje debe tener propietario, título y etapas.")

    # identificador para cada viaje
    viaje_id = uuid4().hex

    itinerario = {
        "titulo": titulo.strip(),
        "etapas": etapas
    }

    # El AAD autentica el identificador y propietario del viaje.
    contexto = _contexto_viaje(viaje_id, propietario)
    datos_cifrados = cifrar_itinerario(itinerario, clave, contexto)

    viajes = cargar_viajes()
    viajes[viaje_id] = {
        "propietario": propietario,
        "contacto": None,
        "datos_cifrados": datos_cifrados
    }

    guardar_viajes(viajes)
    return viaje_id


def _descifrar_viaje_autorizado(
    viaje_id: str, viaje: dict, usuario: str, clave: bytes
) -> dict | None:
    """comprueba los permisos y descifra un itinerario autorizado"""
    # solo el propietario y su contacto pueden consultar el itinerario
    if not usuario or usuario not in (viaje["propietario"], viaje["contacto"]):
        return None

    # Reconstruimos el AAD para verificar la autenticidad del itinerario.
    contexto = _contexto_viaje(viaje_id, viaje["propietario"])

    itinerario = descifrar_itinerario(
        viaje["datos_cifrados"], clave, contexto
    )

    return {
        "id": viaje_id,
        "propietario": viaje["propietario"],
        "contacto": viaje["contacto"],
        "titulo": itinerario["titulo"],
        "etapas": itinerario["etapas"]
    }


def obtener_viaje(
    viaje_id: str, usuario: str, clave: bytes
) -> dict | None:
    """recupera un viaje descifrado si el usuario tiene acceso"""
    viaje = cargar_viajes().get(viaje_id)

    if viaje is None:
        return None

    return _descifrar_viaje_autorizado(viaje_id, viaje, usuario, clave)


def listar_viajes(usuario: str, clave: bytes) -> list[dict]:
    """Devuelve los viajes que puede consultar un usuario"""
    resultado = []

    for viaje_id, viaje in cargar_viajes().items():
        itinerario = _descifrar_viaje_autorizado(
            viaje_id, viaje, usuario, clave
        )

        if itinerario is not None:
            resultado.append(itinerario)

    return resultado