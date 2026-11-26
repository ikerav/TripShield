"""Pruebas de almacenamiento de usuarios."""

import pytest

import storage


@pytest.fixture
def usuario_registrado(tmp_path, monkeypatch):
    """Prepara un usuario ficticio en un archivo temporal."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")

    credenciales = {
        "salt": "00" * 16,
        "hash": "11" * 32
    }

    storage.guardar_usuario("viajero_prueba", credenciales)
    return credenciales


def test_guardar_y_recuperar_usuario(usuario_registrado):
    """Comprueba que se recuperan los datos almacenados."""
    assert storage.buscar_usuario("viajero_prueba") == usuario_registrado
    assert storage.buscar_usuario("no_registrado") is None


def test_rechazar_usuario_duplicado(usuario_registrado):
    """Registrar un nombre existente no sustituye sus datos."""
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        storage.guardar_usuario("viajero_prueba", usuario_registrado)

    assert storage.USERS_FILE.read_bytes() == original


def test_error_de_escritura_conserva_original(usuario_registrado):
    """Una escritura fallida conserva el archivo original."""
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(TypeError):
        storage.guardar_usuario("otro_usuario", {"valor": {1, 2}})

    assert storage.USERS_FILE.read_bytes() == original
    assert not list(storage.USERS_FILE.parent.glob("usuarios_*.tmp"))


@pytest.mark.parametrize("contenido", ["{", "[]", '{"viajero": null}'])
def test_archivo_invalido_no_se_sobrescribe(usuario_registrado, contenido):
    """Un archivo inválido no se reemplaza por datos nuevos."""
    storage.USERS_FILE.write_text(contenido, encoding="utf-8")

    with pytest.raises(ValueError):
        storage.guardar_usuario("nuevo_usuario", usuario_registrado)

    assert storage.USERS_FILE.read_text(encoding="utf-8") == contenido