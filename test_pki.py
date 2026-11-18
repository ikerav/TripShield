"""Pruebas de generación, protección y almacenamiento de la CA."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

import pki
from pki import crear_ca, proteger_clave_ca, desbloquear_clave_ca


PASSWORD_CA_PRUEBA = "Contraseña ficticia de CA para pruebas 2026!"


def test_ca_autofirmada_valida():
    """Comprueba la firma, identidad, vigencia y permisos del certificado raíz."""
    privada, certificado = crear_ca()
    publica = certificado.public_key()

    assert isinstance(publica, Ed25519PublicKey)
    assert publica.public_bytes_raw() == privada.public_key().public_bytes_raw()
    assert certificado.subject == certificado.issuer

    nombre = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(nombre) == 1
    assert nombre[0].value == "TripShield Root CA"
    assert certificado.signature_algorithm_oid == SignatureAlgorithmOID.ED25519

    # La firma debe verificarse con la pública incluida en el certificado raíz.
    publica.verify(certificado.signature, certificado.tbs_certificate_bytes)

    ahora = datetime.now(timezone.utc)
    assert certificado.not_valid_before_utc <= ahora
    assert ahora < certificado.not_valid_after_utc
    assert certificado.serial_number > 0

    restricciones = certificado.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    usos = certificado.extensions.get_extension_for_class(x509.KeyUsage)
    assert restricciones.critical and restricciones.value.ca
    assert restricciones.value.path_length == 0
    assert usos.critical and usos.value.key_cert_sign
    assert not usos.value.digital_signature
    assert not usos.value.key_agreement
    assert not usos.value.key_encipherment


def test_privada_ca_protegida_y_password_incorrecta():
    """Solo la contraseña correcta recupera exactamente la privada original."""
    privada, _ = crear_ca()
    protegida = proteger_clave_ca(privada, PASSWORD_CA_PRUEBA)

    assert protegida.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    recuperada = desbloquear_clave_ca(protegida, PASSWORD_CA_PRUEBA)
    assert recuperada.private_bytes_raw() == privada.private_bytes_raw()

    # Ni una contraseña equivocada ni su ausencia permiten cargar la privada.
    with pytest.raises(ValueError):
        desbloquear_clave_ca(protegida, "Contraseña incorrecta")

    with pytest.raises((TypeError, ValueError)):
        serialization.load_pem_private_key(protegida, password=None)


@pytest.fixture
def directorio_ca(tmp_path, monkeypatch):
    """Dirige todas las operaciones de la CA a un directorio temporal."""
    ruta = tmp_path / "configuracion" / "pki"
    monkeypatch.setattr(pki, "CA_DIRECTORY", ruta)
    return ruta


def test_guardar_y_recuperar_ca(directorio_ca):
    """Recupera el mismo par y comprueba los permisos de los archivos."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    privada, certificado = pki.cargar_ca(PASSWORD_CA_PRUEBA)
    raiz = pki.cargar_certificado_ca()

    assert raiz.public_bytes(serialization.Encoding.DER) == certificado.public_bytes(
        serialization.Encoding.DER
    )
    assert (
        privada.public_key().public_bytes_raw()
        == raiz.public_key().public_bytes_raw()
    )
    assert (directorio_ca / "ca_key.pem").read_bytes().startswith(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    )

    if os.name == "posix":
        assert stat.S_IMODE(directorio_ca.stat().st_mode) == 0o700
        for nombre in ("ca_key.pem", "ca_cert.pem"):
            assert stat.S_IMODE((directorio_ca / nombre).stat().st_mode) == 0o600


def test_ca_existente_no_se_sobrescribe(directorio_ca):
    """Un segundo intento de inicialización conserva exactamente los archivos."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    originales = {
        ruta.name: ruta.read_bytes() for ruta in directorio_ca.iterdir()
    }

    with pytest.raises(FileExistsError):
        pki.inicializar_ca("Otra contraseña ficticia de CA 2026!")

    actuales = {
        ruta.name: ruta.read_bytes() for ruta in directorio_ca.iterdir()
    }
    assert actuales == originales


def test_cargar_ca_rechaza_password_incorrecta(directorio_ca):
    """Una contraseña incorrecta no desbloquea ni modifica la CA guardada."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    original = (directorio_ca / "ca_key.pem").read_bytes()

    with pytest.raises(ValueError):
        pki.cargar_ca("Contraseña incorrecta")

    assert (directorio_ca / "ca_key.pem").read_bytes() == original


def test_rechazar_privada_de_otra_ca(directorio_ca):
    """Una privada válida de otra CA no puede utilizarse con la raíz original."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    otra_privada, _ = pki.crear_ca()
    (directorio_ca / "ca_key.pem").write_bytes(
        pki.proteger_clave_ca(otra_privada, PASSWORD_CA_PRUEBA)
    )

    with pytest.raises(ValueError, match="no corresponde"):
        pki.cargar_ca(PASSWORD_CA_PRUEBA)


@pytest.mark.parametrize("alteracion", ["pem_invalido", "firma_alterada"])
def test_rechazar_raiz_alterada(directorio_ca, alteracion):
    """Rechaza tanto un archivo ilegible como una autofirma incorrecta."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    ruta = directorio_ca / "ca_cert.pem"

    if alteracion == "pem_invalido":
        ruta.write_bytes(b"Esto no es un certificado PEM.")
    else:
        certificado = pki.cargar_certificado_ca()
        der = bytearray(certificado.public_bytes(serialization.Encoding.DER))

        # El último byte pertenece a la firma, no a la estructura del certificado.
        der[-1] ^= 1
        alterado = x509.load_der_x509_certificate(bytes(der))
        ruta.write_bytes(alterado.public_bytes(serialization.Encoding.PEM))

    original = ruta.read_bytes()
    with pytest.raises(ValueError):
        pki.cargar_certificado_ca()

    assert ruta.read_bytes() == original


def test_ca_incompleta_no_se_regenera(directorio_ca):
    """Si falta el certificado, se falla sin reemplazar la privada existente."""
    pki.inicializar_ca(PASSWORD_CA_PRUEBA)
    privada_original = (directorio_ca / "ca_key.pem").read_bytes()
    (directorio_ca / "ca_cert.pem").unlink()

    with pytest.raises(FileNotFoundError):
        pki.cargar_ca(PASSWORD_CA_PRUEBA)

    with pytest.raises(FileExistsError):
        pki.inicializar_ca(PASSWORD_CA_PRUEBA)

    assert (directorio_ca / "ca_key.pem").read_bytes() == privada_original


def test_inicializacion_simultanea_no_sustituye_ca(directorio_ca):
    """Dos inicializaciones simultáneas solo pueden crear una CA."""
    inicio = Barrier(2)

    def inicializar():
        inicio.wait(timeout=5)
        try:
            pki.inicializar_ca(PASSWORD_CA_PRUEBA)
            return "creada"
        except FileExistsError:
            return "rechazada"

    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(lambda _: inicializar(), range(2)))

    assert sorted(resultados) == ["creada", "rechazada"]
    pki.cargar_ca(PASSWORD_CA_PRUEBA)