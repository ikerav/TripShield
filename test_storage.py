"""Pruebas de persistencia de usuarios y claves de firma."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

import storage


@pytest.fixture
def usuario_registrado(tmp_path, monkeypatch):
    """Prepara un usuario ficticio en un archivo temporal aislado."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")
    credenciales = {"salt": "00" * 16, "hash": "11" * 32}
    storage.guardar_usuario("viajero_prueba", credenciales)
    return credenciales


@pytest.fixture
def claves_prueba():
    """Proporciona un registro ficticio para probar su almacenamiento."""
    return {
        "publica": "22" * 32,
        "privada_protegida": {
            "version": 1,
            "salt": "33" * 16,
            "nonce": "44" * 12,
            "cifrado": "55" * 48
        }
    }


def test_conservar_credenciales_y_primeras_claves(
    usuario_registrado, claves_prueba
):
    """Comprueba que añadir claves conserva la cuenta y no sustituye su par."""
    primeras = storage.guardar_claves_firma_si_faltan(
        "viajero_prueba", claves_prueba
    )
    otras = {**claves_prueba, "publica": "66" * 32}
    conservadas = storage.guardar_claves_firma_si_faltan(
        "viajero_prueba", otras
    )
    usuario = storage.buscar_usuario("viajero_prueba")

    assert primeras == conservadas == claves_prueba
    assert usuario["salt"] == usuario_registrado["salt"]
    assert usuario["hash"] == usuario_registrado["hash"]
    assert usuario["claves_firma"] == claves_prueba


def test_rechazar_claves_de_usuario_inexistente(
    usuario_registrado, claves_prueba
):
    """Comprueba que una cuenta inexistente no modifica el archivo."""
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        storage.guardar_claves_firma_si_faltan("no_registrado", claves_prueba)

    assert storage.USERS_FILE.read_bytes() == original


def test_rechazar_usuario_duplicado(usuario_registrado):
    """Comprueba que registrar un nombre existente conserva sus datos."""
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        storage.guardar_usuario("viajero_prueba", usuario_registrado)

    assert storage.USERS_FILE.read_bytes() == original


def test_error_de_escritura_conserva_original(usuario_registrado):
    """Comprueba que una escritura fallida conserva el archivo original."""
    original = storage.USERS_FILE.read_bytes()

    # Un conjunto no se puede guardar como JSON: forzamos un fallo de escritura.
    with pytest.raises(TypeError):
        storage.guardar_usuario("otro_usuario", {"valor": {1, 2}})

    assert storage.USERS_FILE.read_bytes() == original
    assert not list(storage.USERS_FILE.parent.glob("usuarios_*.tmp"))


def test_dos_sesiones_conservan_el_mismo_par(
    usuario_registrado, claves_prueba
):
    """Comprueba que dos intentos simultáneos conservan un único par."""
    inicio = Barrier(2)
    candidatas = [claves_prueba, {**claves_prueba, "publica": "66" * 32}]

    def registrar(claves):
        """Sincroniza el inicio de los dos intentos de registro."""
        inicio.wait(timeout=5)
        return storage.guardar_claves_firma_si_faltan("viajero_prueba", claves)

    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(registrar, candidatas))

    guardadas = storage.buscar_usuario("viajero_prueba")["claves_firma"]
    assert resultados[0] == resultados[1] == guardadas
    assert guardadas in candidatas


@pytest.mark.parametrize("contenido", ["{", "[]", '{"viajero": null}'])
def test_archivo_invalido_no_se_sobrescribe(usuario_registrado, contenido):
    """Comprueba que un archivo inválido no se reemplaza por datos nuevos."""
    storage.USERS_FILE.write_text(contenido, encoding="utf-8")

    with pytest.raises(ValueError):
        storage.guardar_usuario("nuevo_usuario", usuario_registrado)

    assert storage.USERS_FILE.read_text(encoding="utf-8") == contenido