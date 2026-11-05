"""Almacenamiento y consulta de usuarios en archivos JSON"""

import json
from pathlib import Path

USERS_FILE = Path(__file__).resolve().parent / "data" / "users.json"


def cargar_usuarios() -> dict:
    """carga los usuarios almacenados en el archivo JSON"""
    if not USERS_FILE.exists():
        return {}

    with open(USERS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def guardar_usuario(username: str, password_data: dict) -> None:
    """Guarda un usuario con su hash y sal, evitando duplicados"""
    usuarios = cargar_usuarios()

    # evita sobrescribir las credenciales de un usuario existente
    if username in usuarios:
        raise ValueError("El nombre de usuario ya existe.")

    usuarios[username] = password_data

    # crea el directorio de almacenamiento si no existe
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(usuarios, file, indent=4)


def buscar_usuario(username: str) -> dict | None:
    """Busca un usuario y devuelve sus datos si existe."""
    usuarios = cargar_usuarios()
    return usuarios.get(username)