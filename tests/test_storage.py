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


@pytest.fixture
def usuario_con_claves(usuario_registrado, claves_prueba):
    """Añade un par ficticio a la cuenta temporal para probar su certificado."""
    storage.guardar_claves_firma_si_faltan("viajero_prueba", claves_prueba)
    return claves_prueba


def test_certificado_conserva_cuenta_y_primer_registro(
    usuario_con_claves, usuario_registrado
):
    """Añadir o repetir el certificado conserva las credenciales y las claves."""
    publica = usuario_con_claves["publica"]
    primero = storage.guardar_certificado_si_falta(
        "viajero_prueba", "Certificado ficticio inicial", publica
    )
    original = storage.USERS_FILE.read_bytes()
    conservado = storage.guardar_certificado_si_falta(
        "viajero_prueba", "Otro certificado ficticio", publica
    )
    cuenta = storage.buscar_usuario("viajero_prueba")
    claves = cuenta["claves_firma"].copy()

    assert primero == conservado == claves.pop("certificado")
    assert claves == usuario_con_claves
    assert cuenta["salt"] == usuario_registrado["salt"]
    assert cuenta["hash"] == usuario_registrado["hash"]
    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_rechaza_cuenta_inexistente(usuario_con_claves):
    """Un certificado no crea por sí solo una cuenta inexistente."""
    original = storage.USERS_FILE.read_bytes()
    with pytest.raises(ValueError):
        storage.guardar_certificado_si_falta(
            "no_registrado", "Certificado ficticio", usuario_con_claves["publica"]
        )
    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_rechaza_publica_cambiada(usuario_con_claves):
    """Se rechaza el guardado si la clave ya no coincide con la comprobada."""
    original = storage.USERS_FILE.read_bytes()
    with pytest.raises(ValueError, match="cambió"):
        storage.guardar_certificado_si_falta(
            "viajero_prueba", "Certificado ficticio", "99" * 32
        )
    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_requiere_claves_existentes(usuario_registrado):
    """El certificado no sustituye la necesidad de tener un par de firma."""
    original = storage.USERS_FILE.read_bytes()
    with pytest.raises(ValueError):
        storage.guardar_certificado_si_falta(
            "viajero_prueba", "Certificado ficticio", "22" * 32
        )
    assert storage.USERS_FILE.read_bytes() == original


@pytest.mark.parametrize("certificado", [None, ""])
def test_certificado_invalido_no_se_sustituye(
    usuario_con_claves, certificado
):
    """Un certificado dañado se rechaza sin reemplazarlo automáticamente."""
    usuarios = storage.cargar_usuarios()
    usuarios["viajero_prueba"]["claves_firma"]["certificado"] = certificado
    storage._guardar_usuarios(usuarios)
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        storage.guardar_certificado_si_falta(
            "viajero_prueba", "Certificado nuevo", usuario_con_claves["publica"]
        )
    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_rechaza_entrada_invalida(usuario_con_claves):
    """Un valor vacío o mal tipado no modifica el archivo de cuentas."""
    original = storage.USERS_FILE.read_bytes()

    for certificado in (None, ""):
        with pytest.raises(ValueError):
            storage.guardar_certificado_si_falta(
                "viajero_prueba", certificado, usuario_con_claves["publica"]
            )
    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_simultaneo_conserva_el_primero(usuario_con_claves):
    """Dos sesiones concurrentes reciben el mismo certificado persistido."""
    inicio = Barrier(2)

    def guardar(certificado):
        inicio.wait(timeout=5)
        return storage.guardar_certificado_si_falta(
            "viajero_prueba", certificado, usuario_con_claves["publica"]
        )

    candidatos = ["Certificado ficticio A", "Certificado ficticio B"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(guardar, candidatos))

    cuenta = storage.buscar_usuario("viajero_prueba")
    guardado = cuenta["claves_firma"]["certificado"]
    assert resultados[0] == resultados[1] == guardado
    assert guardado in candidatos