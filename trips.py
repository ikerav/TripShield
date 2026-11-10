"""Gestión y almacenamiento de itinerarios cifrados de TripShield."""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import RLock
from uuid import uuid4

from encryption import cifrar_itinerario, descifrar_itinerario
from storage import buscar_usuario


TRIPS_FILE = Path(__file__).resolve().parent / "data" / "trips.json"
_VIAJES_LOCK = RLock()


def _contexto_viaje(
    viaje_id: str, propietario: str, contacto: str | None = None
) -> bytes:
    """Construye el AAD del viaje, incluyendo el contacto si está compartido."""
    if contacto is None:
        return f"TripShield:viaje:{viaje_id}:{propietario}".encode("utf-8")

    datos = {
        "id": viaje_id,
        "propietario": propietario,
        "contacto": contacto
    }

    # Incluimos el contacto en el AAD para proteger los permisos de acceso.
    contexto = json.dumps(datos, sort_keys=True, ensure_ascii=False)
    return f"TripShield:viaje:compartido:v1:{contexto}".encode("utf-8")


def cargar_viajes() -> dict:
    """Carga los viajes y rechaza un archivo con estructura incorrecta."""
    if not TRIPS_FILE.exists():
        return {}

    with open(TRIPS_FILE, "r", encoding="utf-8") as file:
        viajes = json.load(file)

    if not isinstance(viajes, dict) or any(
        not isinstance(viaje, dict) for viaje in viajes.values()
    ):
        raise ValueError("El archivo de viajes tiene un formato inválido.")

    return viajes


def guardar_viajes(viajes: dict) -> None:
    """Guarda los viajes mediante un reemplazo atómico del archivo."""
    with _VIAJES_LOCK:
        TRIPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporal = None

        try:
            # El temporal se crea junto al original y con permisos restrictivos.
            with NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=TRIPS_FILE.parent,
                prefix="viajes_", suffix=".tmp", delete=False
            ) as file:
                temporal = Path(file.name)
                json.dump(
                    viajes, file, indent=4,
                    ensure_ascii=False, allow_nan=False
                )
                file.flush()
                os.fsync(file.fileno())

            temporal.replace(TRIPS_FILE)
        finally:
            if temporal is not None:
                temporal.unlink(missing_ok=True)


def crear_viaje(
    propietario: str, titulo: str, etapas: list[dict], clave: bytes
) -> str:
    """Crea un viaje y almacena su itinerario cifrado."""
    if not propietario or not titulo.strip() or not etapas:
        raise ValueError("El viaje debe tener propietario, título y etapas.")

    viaje_id = uuid4().hex
    itinerario = {"titulo": titulo.strip(), "etapas": etapas}
    contexto = _contexto_viaje(viaje_id, propietario)
    datos_cifrados = cifrar_itinerario(itinerario, clave, contexto)

    # Protegemos la lectura y el guardado para conservar otros cambios.
    with _VIAJES_LOCK:
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
    """Comprueba los permisos y descifra un itinerario autorizado."""
    # Solo el propietario y su contacto pueden consultar el itinerario.
    if not usuario or usuario not in (
        viaje["propietario"], viaje["contacto"]
    ):
        return None

    contexto = _contexto_viaje(
        viaje_id, viaje["propietario"], viaje["contacto"]
    )
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
    """Recupera un viaje descifrado si el usuario tiene acceso."""
    viaje = cargar_viajes().get(viaje_id)

    if viaje is None:
        return None

    return _descifrar_viaje_autorizado(viaje_id, viaje, usuario, clave)


def listar_viajes(usuario: str, clave: bytes) -> list[dict]:
    """Devuelve los viajes que puede consultar un usuario."""
    resultado = []

    for viaje_id, viaje in cargar_viajes().items():
        itinerario = _descifrar_viaje_autorizado(
            viaje_id, viaje, usuario, clave
        )
        if itinerario is not None:
            resultado.append(itinerario)

    return resultado


def _recifrar_viaje_para_contacto(
    viaje_id: str, viaje: dict, contacto: str, clave: bytes
) -> dict:
    """Vuelve a cifrar el itinerario incluyendo el contacto en el AAD."""
    propietario = viaje["propietario"]

    # Desciframos utilizando el AAD original, sin contacto.
    contexto_anterior = _contexto_viaje(viaje_id, propietario)
    itinerario = descifrar_itinerario(
        viaje["datos_cifrados"], clave, contexto_anterior
    )

    # El nuevo AAD también autentica al contacto de confianza.
    contexto_nuevo = _contexto_viaje(viaje_id, propietario, contacto)
    return cifrar_itinerario(itinerario, clave, contexto_nuevo)


def _validar_contacto(propietario: str, contacto: str, viaje: dict) -> None:
    """Comprueba que el contacto puede ser asignado al viaje."""
    if not contacto or contacto == propietario:
        raise ValueError("Debes elegir otro usuario como contacto.")

    if buscar_usuario(contacto) is None:
        raise ValueError("El contacto debe estar registrado en TripShield.")

    if viaje["contacto"] is not None:
        raise ValueError("Este viaje ya tiene un contacto de confianza.")


def compartir_viaje(
    viaje_id: str, propietario: str, contacto: str, clave: bytes
) -> None:
    """Comparte un viaje con otro usuario registrado."""
    with _VIAJES_LOCK:
        viajes = cargar_viajes()
        viaje = viajes.get(viaje_id)

        if viaje is None or viaje["propietario"] != propietario:
            raise ValueError("No tienes permiso para compartir este viaje.")

        contacto = contacto.strip()
        _validar_contacto(propietario, contacto, viaje)

        viaje["datos_cifrados"] = _recifrar_viaje_para_contacto(
            viaje_id, viaje, contacto, clave
        )
        viaje["contacto"] = contacto
        guardar_viajes(viajes)


def _crear_mensaje_llegada(
    viaje_id: str, propietario: str, indice: int,
    etapa: dict, confirmado_en: str
) -> dict:
    """Construye una declaración vinculada al viaje, usuario y etapa."""
    if not isinstance(viaje_id, str) or not viaje_id.strip():
        raise ValueError("El viaje debe tener un identificador válido.")

    if not isinstance(propietario, str) or not propietario.strip():
        raise ValueError("La declaración debe tener un propietario.")

    if type(indice) is not int or indice < 0:
        raise ValueError("El índice de la etapa debe ser un entero no negativo.")

    campos = ("destino", "fecha", "hora")
    if not isinstance(etapa, dict) or not all(
        isinstance(etapa.get(campo), str) and etapa[campo].strip()
        for campo in campos
    ):
        raise ValueError("La etapa debe tener destino, fecha y hora.")

    try:
        instante = datetime.fromisoformat(confirmado_en)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "La fecha de confirmación debe ser válida."
        ) from error

    if instante.tzinfo is None or instante.utcoffset() != timedelta(0):
        raise ValueError(
            "La fecha de confirmación debe estar expresada en UTC."
        )

    return {
        "version": 1,
        "viaje_id": viaje_id,
        "etapa_indice": indice,
        "propietario": propietario,
        # Copiamos solo los datos de la etapa que vincularemos a la firma.
        "etapa": {campo: etapa[campo] for campo in campos},
        "confirmado_en": confirmado_en
    }