"""Pruebas de registro, autenticación y claves de firma por usuario."""

import json

import pytest
from cryptography.exceptions import InvalidTag

import auth
import storage
from signatures import (
    desbloquear_clave_privada,
    firmar_confirmacion,
    verificar_confirmacion
)


USUARIO_PRUEBA = "viajero_prueba"
PASSWORD_PRUEBA = "Clave ficticia de usuario 2026!"


@pytest.fixture
def archivo_usuarios(tmp_path, monkeypatch):
    """Aísla los datos de las cuentas en un archivo temporal."""
    ruta = tmp_path / "users.json"
    monkeypatch.setattr(storage, "USERS_FILE", ruta)
    return ruta


def _comprobar_claves_utilizables(cuenta: dict) -> None:
    """Comprueba que la cuenta de prueba puede firmar y verificar."""
    claves = cuenta["claves_firma"]
    privada = desbloquear_clave_privada(
        claves["privada_protegida"], PASSWORD_PRUEBA, USUARIO_PRUEBA
    )
    publica = bytes.fromhex(claves["publica"])
    mensaje = {
        "viaje_id": "viaje_prueba",
        "etapa_indice": 0,
        "propietario": USUARIO_PRUEBA
    }
    firma = firmar_confirmacion(mensaje, privada)

    assert len(publica) == 32
    assert verificar_confirmacion(mensaje, firma, publica)


def test_registrar_usuario_con_claves(archivo_usuarios):
    """Comprueba que una cuenta nueva tiene credenciales y claves utilizables."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    cuenta = storage.buscar_usuario(USUARIO_PRUEBA)

    assert auth.verify_password(PASSWORD_PRUEBA, cuenta)
    assert "password" not in cuenta
    _comprobar_claves_utilizables(cuenta)


def test_login_conserva_claves_existentes(archivo_usuarios):
    """Comprueba que iniciar sesión no sustituye ni reescribe las claves."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    original = archivo_usuarios.read_bytes()

    assert auth.autenticar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    assert auth.autenticar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    assert archivo_usuarios.read_bytes() == original


def test_login_actualiza_cuenta_antigua(archivo_usuarios):
    """Comprueba la incorporación de claves sin perder credenciales ni cuentas."""
    credenciales = auth.hash_password(PASSWORD_PRUEBA)
    storage.guardar_usuario(USUARIO_PRUEBA, credenciales)
    storage.guardar_usuario(
        "otro_usuario", auth.hash_password("Otra clave ficticia de prueba")
    )
    otra_cuenta = storage.buscar_usuario("otro_usuario")

    assert auth.autenticar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    cuenta = storage.buscar_usuario(USUARIO_PRUEBA)

    assert cuenta["salt"] == credenciales["salt"]
    assert cuenta["hash"] == credenciales["hash"]
    assert storage.buscar_usuario("otro_usuario") == otra_cuenta
    _comprobar_claves_utilizables(cuenta)


@pytest.mark.parametrize(
    "usuario, password",
    [
        (USUARIO_PRUEBA, "Incorrecta123"),
        ("no_registrado", PASSWORD_PRUEBA)
    ]
)
def test_login_incorrecto_no_modifica_cuentas(
    archivo_usuarios, usuario, password
):
    """Comprueba que un acceso fallido no crea claves ni cambia las cuentas."""
    storage.guardar_usuario(USUARIO_PRUEBA, auth.hash_password(PASSWORD_PRUEBA))
    original = archivo_usuarios.read_bytes()

    assert not auth.autenticar_usuario(usuario, password)
    assert archivo_usuarios.read_bytes() == original
    assert "claves_firma" not in storage.buscar_usuario(USUARIO_PRUEBA)


def test_registro_duplicado_conserva_cuenta(archivo_usuarios):
    """Comprueba que repetir el registro no sustituye credenciales ni claves."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    original = archivo_usuarios.read_bytes()

    with pytest.raises(ValueError):
        auth.registrar_usuario(USUARIO_PRUEBA, "Otra contraseña ficticia 2026")

    assert archivo_usuarios.read_bytes() == original


@pytest.mark.parametrize(
    "usuario, password",
    [("ab", PASSWORD_PRUEBA), (USUARIO_PRUEBA, "corta")]
)
def test_rechazar_registro_invalido(archivo_usuarios, usuario, password):
    """Comprueba que entradas inválidas no crean un archivo de cuentas."""
    with pytest.raises(ValueError):
        auth.registrar_usuario(usuario, password)

    assert not archivo_usuarios.exists()


def test_obtener_clave_firma_permite_firmar(archivo_usuarios):
    """Comprueba que el desbloqueo devuelve una clave de firma utilizable."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    original = archivo_usuarios.read_bytes()

    privada = auth.obtener_clave_firma_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    cuenta = storage.buscar_usuario(USUARIO_PRUEBA)
    publica = bytes.fromhex(cuenta["claves_firma"]["publica"])
    mensaje = {"viaje_id": "viaje_prueba", "etapa_indice": 0}
    firma = firmar_confirmacion(mensaje, privada)

    assert verificar_confirmacion(mensaje, firma, publica)
    assert archivo_usuarios.read_bytes() == original


@pytest.mark.parametrize(
    "usuario, password",
    [
        (USUARIO_PRUEBA, "Incorrecta123"),
        ("no_registrado", PASSWORD_PRUEBA)
    ]
)
def test_desbloqueo_rechaza_credenciales_incorrectas(
    archivo_usuarios, usuario, password
):
    """Comprueba que un intento fallido no devuelve la clave ni cambia datos."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    original = archivo_usuarios.read_bytes()

    with pytest.raises(ValueError):
        auth.obtener_clave_firma_usuario(usuario, password)

    assert archivo_usuarios.read_bytes() == original


def test_desbloqueo_rechaza_privada_manipulada(archivo_usuarios):
    """Comprueba que una privada cifrada modificada se rechaza sin sustituirla."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    usuarios = json.loads(archivo_usuarios.read_text(encoding="utf-8"))
    protegida = usuarios[USUARIO_PRUEBA]["claves_firma"]["privada_protegida"]

    # Simulamos un cambio en el archivo de prueba, conservando la contraseña.
    cifrado = bytearray.fromhex(protegida["cifrado"])
    cifrado[0] ^= 1
    protegida["cifrado"] = cifrado.hex()
    archivo_usuarios.write_text(json.dumps(usuarios), encoding="utf-8")
    original = archivo_usuarios.read_bytes()

    with pytest.raises(InvalidTag):
        auth.obtener_clave_firma_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)

    assert archivo_usuarios.read_bytes() == original


@pytest.mark.parametrize("claves_invalidas", [None, {}])
def test_desbloqueo_rechaza_registro_invalido(
    archivo_usuarios, claves_invalidas
):
    """Comprueba que un registro dañado no provoca una regeneración de claves."""
    auth.registrar_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)
    usuarios = json.loads(archivo_usuarios.read_text(encoding="utf-8"))
    usuarios[USUARIO_PRUEBA]["claves_firma"] = claves_invalidas
    archivo_usuarios.write_text(json.dumps(usuarios), encoding="utf-8")
    original = archivo_usuarios.read_bytes()

    with pytest.raises(ValueError):
        auth.obtener_clave_firma_usuario(USUARIO_PRUEBA, PASSWORD_PRUEBA)

    assert archivo_usuarios.read_bytes() == original