"""Pruebas de registro certificado y uso de claves por cuenta."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import auth
import pki
import storage
import trips
from signatures import verificar_confirmacion
from setup_local import crear_ca as crear_ca_prueba


USUARIO = "ana"
PASSWORD = "Contraseña ficticia de usuario 2026!"
PASSWORD_CA = "Contraseña ficticia independiente de CA 2026!"


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    """Aísla las cuentas, viajes y autoridad de certificación de laboratorio."""
    monkeypatch.setattr(storage, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(trips, "TRIPS_FILE", tmp_path / "trips.json")
    monkeypatch.setattr(pki, "CA_DIRECTORY", tmp_path / "pki")
    crear_ca_prueba(pki.CA_DIRECTORY, PASSWORD_CA)
    return tmp_path


def _modificar_claves(**cambios):
    """Introduce alteraciones deliberadas solo en el archivo temporal de prueba."""
    usuarios = storage.cargar_usuarios()
    usuarios[USUARIO]["claves_firma"].update(cambios)
    storage._guardar_usuarios(usuarios)



def test_registro_fallido_no_crea_cuenta_incompleta(entorno):
    """El fallo al desbloquear la CA impide guardar el nuevo usuario."""
    with pytest.raises(ValueError):
        auth.registrar_usuario(USUARIO, PASSWORD, "CA incorrecta")

    assert not storage.USERS_FILE.exists()


@pytest.mark.parametrize("tipo", ["nulo", "otra_cuenta", "otra_ca"])
def test_certificado_invalido_no_se_regenera(entorno, monkeypatch, tipo):
    """Un certificado ya asociado que falle se rechaza sin sustituirlo."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    publica = auth.obtener_publica_firma_usuario(USUARIO)

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
            crear_ca_prueba(pki.CA_DIRECTORY, PASSWORD_CA)
            certificado = pki.emitir_certificado_usuario(
                USUARIO, publica, PASSWORD_CA
            )

    _modificar_claves(certificado=certificado)
    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        auth.autenticar_usuario(USUARIO, PASSWORD)
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
    _modificar_claves(certificado=certificado)

    with pytest.raises(ValueError, match="no coinciden"):
        auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)


def test_cuenta_certificada_no_desbloquea_ca_para_acceder_o_firmar(entorno):
    """Con certificado vigente, acceder y firmar no requieren la privada de CA."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)
    (pki.CA_DIRECTORY / "ca_key.pem").unlink()

    assert auth.autenticar_usuario(USUARIO, PASSWORD)
    assert len(auth.obtener_publica_firma_usuario(USUARIO)) == 32
    assert len(auth.obtener_clave_firma_usuario(USUARIO, PASSWORD)) == 32


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

    publica = auth.obtener_publica_firma_usuario(USUARIO)
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
                crear_ca_prueba(pki.CA_DIRECTORY, PASSWORD_CA)
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


def test_login_rechaza_certificado_ausente(entorno):
    """No se emite automáticamente un certificado que falta."""
    auth.registrar_usuario(USUARIO, PASSWORD, PASSWORD_CA)

    usuarios = storage.cargar_usuarios()
    del usuarios[USUARIO]["claves_firma"]["certificado"]
    storage._guardar_usuarios(usuarios)

    original = storage.USERS_FILE.read_bytes()

    with pytest.raises(ValueError):
        auth.autenticar_usuario(USUARIO, PASSWORD)

    assert storage.USERS_FILE.read_bytes() == original