"""Pruebas de registro certificado, migración y uso de claves por cuenta."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import auth
import pki
import storage
import trips
from signatures import (
    generar_claves_firma,
    proteger_clave_privada,
    firmar_confirmacion,
    verificar_confirmacion
)


USUARIO = "ana"
PASSWORD = "Contraseña ficticia de usuario 2026!"
PASSWORD_CA = "Contraseña ficticia independiente de CA 2026!"


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    """Aísla las cuentas, viajes y autoridad de certificación de laboratorio."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(trips, "TRIPS_FILE", tmp_path / "trips.json")
    monkeypatch.setattr(pki, "CA_DIRECTORY", tmp_path / "pki")
    pki.inicializar_ca(PASSWORD_CA)
    return tmp_path


def _cuenta_sin_certificado():
    """Prepara una cuenta del formato anterior conservando su par original."""
    privada, publica = generar_claves_firma()
    cuenta = auth.hash_password(PASSWORD)
    cuenta["claves_firma"] = {
        "publica": publica.hex(),
        "privada_protegida": proteger_clave_privada(
            privada, PASSWORD, USUARIO
        )
    }
    storage.guardar_usuario(USUARIO, cuenta)
    return privada, publica, cuenta


def _modificar_claves(**cambios):
    """Introduce alteraciones deliberadas solo en el archivo temporal de prueba."""
    usuarios = storage.cargar_usuarios()
    usuarios[USUARIO]["claves_firma"].update(cambios)
    storage._guardar_usuarios(usuarios)


def test_migracion_conserva_claves_y_firmas(entorno):
    """El certificado nuevo conserva credenciales, privada y firmas anteriores."""
    privada, publica, original = _cuenta_sin_certificado()
    mensaje = {"viaje_id": "viaje_antiguo", "propietario": USUARIO}
    firma = firmar_confirmacion(mensaje, privada)

    assert auth.autenticar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    cuenta = storage.buscar_usuario(USUARIO)
    assert cuenta["salt"] == original["salt"]
    assert cuenta["hash"] == original["hash"]

    claves = cuenta["claves_firma"].copy()
    certificado = claves.pop("certificado")
    assert claves == original["claves_firma"]
    assert pki.validar_certificado_usuario(certificado, USUARIO) == publica
    assert verificar_confirmacion(
        mensaje, firma, auth.obtener_publica_firma_usuario(USUARIO)
    )
    assert auth.obtener_clave_firma_usuario(USUARIO, PASSWORD) == privada


def test_migracion_rechaza_publica_sustituida(entorno, monkeypatch):
    """No se certifica una pública que no corresponde a la privada del usuario."""
    _cuenta_sin_certificado()
    otra_publica = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    _modificar_claves(publica=otra_publica.hex())
    original = storage.USERS_FILE.read_bytes()

    def no_emitir(*args):
        raise AssertionError("No se debe certificar una clave ajena")

    monkeypatch.setattr(auth, "emitir_certificado_usuario", no_emitir)
    with pytest.raises(ValueError, match="no coinciden"):
        auth.autenticar_usuario(USUARIO, PASSWORD, PASSWORD_CA)

    assert storage.USERS_FILE.read_bytes() == original


def test_migracion_rechaza_privada_alterada(entorno):
    """Una privada cifrada manipulada no obtiene un certificado."""
    _, _, cuenta = _cuenta_sin_certificado()
    protegida = cuenta["claves_firma"]["privada_protegida"].copy()
    cifrado = bytearray.fromhex(protegida["cifrado"])
    cifrado[0] ^= 1
    protegida["cifrado"] = cifrado.hex()
    _modificar_claves(privada_protegida=protegida)
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(InvalidTag):
        auth.autenticar_usuario(USUARIO, PASSWORD, PASSWORD_CA)

    assert storage.USERS_FILE.read_bytes() == original


def test_migracion_requiere_password_correcta(entorno):
    """Un intento de acceso fallido no emite ni almacena un certificado."""
    _cuenta_sin_certificado()
    original = storage.USERS_FILE.read_bytes()

    assert not auth.autenticar_usuario(
        USUARIO, "Incorrecta", "Otra CA incorrecta"
    )
    assert storage.USERS_FILE.read_bytes() == original


def test_registro_fallido_no_crea_cuenta_incompleta(entorno):
    """El fallo al desbloquear la CA impide guardar el nuevo usuario."""
    with pytest.raises(ValueError):
        auth.registrar_usuario(USUARIO, PASSWORD, "CA incorrecta")

    assert not storage.USERS_FILE.exists()


@pytest.mark.parametrize("tipo", ["nulo", "otra_cuenta", "otra_ca"])
def test_certificado_invalido_no_se_regenera(entorno, monkeypatch, tipo):
    """Un certificado ya asociado que falle se rechaza sin sustituirlo."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    cuenta = storage.buscar_usuario(USUARIO)
    publica = bytes.fromhex(cuenta["claves_firma"]["publica"])

    if tipo == "nulo":
        certificado = None
    elif tipo == "otra_cuenta":
        certificado = pki.emitir_certificado_usuario(
            "bob", publica, PASSWORD_CA
        )
    else:
        with monkeypatch.context() as otra_configuracion:
            otra_configuracion.setattr(
                pki, "CA_DIRECTORY", entorno / "otra_ca"
            )
            pki.inicializar_ca(PASSWORD_CA)
            certificado = pki.emitir_certificado_usuario(
                USUARIO, publica, PASSWORD_CA
            )

    _modificar_claves(certificado=certificado)
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        auth.autenticar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    with pytest.raises(ValueError):
        auth.obtener_publica_firma_usuario(USUARIO)
    with pytest.raises(ValueError):
        auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)

    assert storage.USERS_FILE.read_bytes() == original


def test_certificado_y_publica_deben_coincidir(entorno):
    """Cambiar la pública del JSON no sustituye la pública certificada."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    otra_publica = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    _modificar_claves(publica=otra_publica.hex())
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        auth.obtener_publica_firma_usuario(USUARIO)
    with pytest.raises(ValueError):
        auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)

    assert storage.USERS_FILE.read_bytes() == original


def test_privada_debe_corresponder_a_clave_certificada(entorno):
    """Un certificado de otra clave no autoriza el uso de la privada original."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    otra_publica = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    certificado = pki.emitir_certificado_usuario(
        USUARIO, otra_publica, PASSWORD_CA
    )
    _modificar_claves(
        publica=otra_publica.hex(), certificado=certificado
    )

    with pytest.raises(ValueError, match="no coinciden"):
        auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)


def test_cuenta_certificada_no_desbloquea_ca_para_acceder_o_firmar(entorno):
    """Con certificado vigente, acceder y firmar no requieren la privada de CA."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    (pki.CA_DIRECTORY / "ca_key.pem").unlink()

    assert auth.autenticar_usuario(
        USUARIO, PASSWORD, "No se utiliza para validar"
    )
    assert len(auth.obtener_publica_firma_usuario(USUARIO)) == 32
    assert len(auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)) == 32


def test_migracion_simultanea_conserva_par_original(entorno):
    """Dos accesos simultáneos certifican el mismo par sin sustituirlo."""
    _, publica, original = _cuenta_sin_certificado()
    inicio = Barrier(2)

    def autenticar():
        inicio.wait(timeout=5)
        return auth.autenticar_usuario(USUARIO, PASSWORD, PASSWORD_CA)

    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(lambda _: autenticar(), range(2)))

    assert resultados == [True, True]
    claves = storage.buscar_usuario(USUARIO)["claves_firma"].copy()
    claves.pop("certificado")
    assert claves == original["claves_firma"]
    assert auth.obtener_publica_firma_usuario(USUARIO) == publica


@pytest.mark.parametrize("usuario", ["desconocido", "", None])
def test_publica_rechaza_cuenta_invalida(entorno, usuario):
    """Una cuenta ausente o mal indicada no devuelve una clave pública."""
    with pytest.raises(ValueError):
        auth.obtener_publica_firma_usuario(usuario)


@pytest.mark.parametrize("fallo", ["otro_usuario", "otra_ca", "sin_raiz"])
def test_firma_correcta_con_certificado_invalido_no_se_acepta(
    entorno, monkeypatch, fallo
):
    """El contacto rechaza una firma correcta si falla el certificado del dueño."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    storage.guardar_usuario(
        "contacto", auth.hash_password("Otra contraseña ficticia")
    )
    clave = AESGCM.generate_key(bit_length=256)
    viaje_id = trips.crear_viaje(
        USUARIO,
        "Viaje ficticio",
        [{
            "destino": "Berlín",
            "fecha": "2026-12-12",
            "hora": "12:30"
        }],
        clave
    )
    trips.compartir_viaje(viaje_id, USUARIO, "contacto", PASSWORD, clave)
    trips.confirmar_llegada(viaje_id, USUARIO, 0, PASSWORD, clave)

    cuenta = storage.buscar_usuario(USUARIO)
    publica = bytes.fromhex(cuenta["claves_firma"]["publica"])
    viaje = trips.obtener_viaje(viaje_id, "contacto", clave)
    confirmacion = viaje["etapas"][0]["confirmacion"]

    assert verificar_confirmacion(
        confirmacion["mensaje"],
        bytes.fromhex(confirmacion["firma"]),
        publica
    )

    if fallo == "sin_raiz":
        (pki.CA_DIRECTORY / "ca_cert.pem").unlink()
    else:
        if fallo == "otro_usuario":
            certificado = pki.emitir_certificado_usuario(
                "bob", publica, PASSWORD_CA
            )
        else:
            with monkeypatch.context() as otra_configuracion:
                otra_configuracion.setattr(
                    pki, "CA_DIRECTORY", entorno / "otra_ca"
                )
                pki.inicializar_ca(PASSWORD_CA)
                certificado = pki.emitir_certificado_usuario(
                    USUARIO, publica, PASSWORD_CA
                )
        _modificar_claves(certificado=certificado)

    assert trips.verificar_llegada(
        viaje_id, "contacto", 0, clave
    ) is False


def test_identificador_no_puede_absorber_parte_del_propietario(entorno):
    """El ID de longitud fija evita ambigüedades en el AAD de viajes antiguos."""
    clave = AESGCM.generate_key(bit_length=256)
    viaje_id = trips.crear_viaje(
        "uno:dos",
        "Viaje ficticio",
        [{
            "destino": "Prueba",
            "fecha": "2026-12-12",
            "hora": "12:30"
        }],
        clave
    )
    assert trips.obtener_viaje(viaje_id, "uno:dos", clave) is not None

    registros = trips.cargar_viajes()
    registro = registros.pop(viaje_id)
    registro["propietario"] = "dos"
    falso_id = viaje_id + ":uno"
    registros[falso_id] = registro
    trips.guardar_viajes(registros)

    with pytest.raises(ValueError, match="identificador"):
        trips.obtener_viaje(falso_id, "dos", clave)