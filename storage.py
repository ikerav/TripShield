"""Almacenamiento de usuarios y claves de firma protegidas en JSON."""

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Lock


USERS_FILE = Path(__file__).resolve().parent / "data" / "users.json"
_USUARIOS_LOCK = Lock()


def cargar_usuarios() -> dict:
    """Carga los usuarios y rechaza un archivo con estructura incorrecta."""
    if not USERS_FILE.exists():
        return {}

    with open(USERS_FILE, "r", encoding="utf-8") as file:
        usuarios = json.load(file)

    if not isinstance(usuarios, dict) or any(
        not isinstance(datos, dict) for datos in usuarios.values()
    ):
        raise ValueError("El archivo de usuarios tiene un formato inválido.")

    return usuarios


def _guardar_usuarios(usuarios: dict) -> None:
    """Escribe los usuarios mediante un reemplazo atómico del archivo."""
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporal = None

    try:
        # El temporal se crea en la misma carpeta y con permisos restrictivos.
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=USERS_FILE.parent,
            prefix="usuarios_", suffix=".tmp", delete=False
        ) as file:
            temporal = Path(file.name)
            json.dump(
                usuarios, file, indent=4,
                ensure_ascii=False, allow_nan=False
            )
            file.flush()
            os.fsync(file.fileno())

        temporal.replace(USERS_FILE)
    finally:
        # Si la escritura falla, retiramos el temporal y conservamos el original.
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def guardar_usuario(username: str, password_data: dict) -> None:
    """Guarda un usuario con sus credenciales, evitando duplicados."""
    if not username or not isinstance(password_data, dict):
        raise ValueError(
            "Debes indicar un usuario y sus datos de autenticación."
        )

    # El bloqueo protege la lectura y escritura entre sesiones del proceso.
    with _USUARIOS_LOCK:
        usuarios = cargar_usuarios()
        if username in usuarios:
            raise ValueError("El nombre de usuario ya existe.")

        usuarios[username] = password_data
        _guardar_usuarios(usuarios)


def buscar_usuario(username: str) -> dict | None:
    """Busca un usuario y devuelve sus datos si existe."""
    return cargar_usuarios().get(username)


def guardar_claves_firma_si_faltan(username: str, claves: dict) -> dict:
    """Guarda el primer par de claves y devuelve el registro asociado."""
    if not isinstance(claves, dict):
        raise ValueError(
            "Las claves de firma deben proporcionarse como diccionario."
        )

    with _USUARIOS_LOCK:
        usuarios = cargar_usuarios()
        usuario = usuarios.get(username)
        if usuario is None:
            raise ValueError("El usuario debe estar registrado.")

        # Conservamos las claves existentes para no invalidar firmas anteriores.
        if "claves_firma" in usuario:
            existentes = usuario["claves_firma"]
            if not isinstance(existentes, dict):
                raise ValueError("El registro de claves de firma es inválido.")
            return existentes

        usuario["claves_firma"] = claves
        _guardar_usuarios(usuarios)
        return claves


def guardar_certificado_si_falta(
    username: str, certificado: str, publica_esperada: str
) -> str:
    """Asocia el primer certificado a las claves existentes de una cuenta."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Debes indicar un usuario válido.")
    if not isinstance(certificado, str) or not certificado.strip():
        raise ValueError("Debes proporcionar el certificado como texto.")
    if not isinstance(publica_esperada, str) or not publica_esperada.strip():
        raise ValueError("Debes indicar la clave pública esperada.")

    with _USUARIOS_LOCK:
        usuarios = cargar_usuarios()
        usuario = usuarios.get(username)
        if usuario is None:
            raise ValueError("El usuario debe estar registrado.")

        claves = usuario.get("claves_firma")
        if not isinstance(claves, dict):
            raise ValueError("La cuenta no tiene un registro de claves válido.")
        if claves.get("publica") != publica_esperada:
            raise ValueError("La clave pública cambió durante la operación.")

        # Si otra sesión ya guardó el certificado, conservamos ese primero.
        if "certificado" in claves:
            existente = claves["certificado"]
            if not isinstance(existente, str) or not existente.strip():
                raise ValueError("El registro del certificado es inválido.")
            return existente

        claves["certificado"] = certificado
        _guardar_usuarios(usuarios)
        return certificado