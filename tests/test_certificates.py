"""Pruebas de emisión, identidad y validación de certificados de usuario."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.x509.oid import NameOID, ObjectIdentifier

import pki
from setup_local import crear_ca as crear_ca_prueba


PASSWORD_CA_PRUEBA = "Contraseña ficticia de CA para pruebas 2026!"


@pytest.fixture
def publica_usuario(tmp_path, monkeypatch):
    """Prepara una CA temporal y una clave pública ficticia de usuario."""
    monkeypatch.setattr(pki, "CA_DIRECTORY", tmp_path / "ca")
    crear_ca_prueba(pki.CA_DIRECTORY, PASSWORD_CA_PRUEBA)
    privada = Ed25519PrivateKey.generate()
    return privada.public_key().public_bytes_raw()


def _crear_certificado_prueba(publica, *, inicio=None, fin=None, perfil="firma"):
    """Firma certificados de laboratorio con campos deliberadamente variables."""
    raiz = pki.cargar_certificado_ca()
    privada_ca = serialization.load_pem_private_key(
        (pki.CA_DIRECTORY / "ca_key.pem").read_bytes(),
        password=PASSWORD_CA_PRUEBA.encode("utf-8")
    )
    ahora = datetime.now(timezone.utc)

    if perfil == "rsa":
        clave = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        ).public_key()
    else:
        clave = Ed25519PublicKey.from_public_bytes(publica)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ana")
        ]))
        .issuer_name(raiz.subject)
        .public_key(clave)
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio or ahora - timedelta(minutes=1))
        .not_valid_after(fin or ahora + timedelta(days=30))
    )

    if perfil != "sin_extensiones":
        es_ca = perfil == "ca"
        builder = builder.add_extension(
            x509.BasicConstraints(ca=es_ca, path_length=0 if es_ca else None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=perfil != "sin_firma",
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=es_ca,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(clave),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            raiz.public_key()
        ),
        critical=False
    )

    if perfil == "critica":
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.2.3.4"), b"\x05\x00"
            ),
            critical=True
        )

    return builder.sign(privada_ca, None).public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")


def test_emitir_y_validar_usuario(publica_usuario):
    """El certificado aceptado contiene exactamente la pública del usuario."""
    datos = pki.emitir_certificado_usuario(
        "ana", publica_usuario, PASSWORD_CA_PRUEBA
    )
    assert pki.validar_certificado_usuario(datos, "ana") == publica_usuario

    cert = x509.load_pem_x509_certificate(datos.encode("ascii"))
    raiz = pki.cargar_certificado_ca()
    assert cert.not_valid_after_utc <= raiz.not_valid_after_utc
    assert cert.not_valid_before_utc >= raiz.not_valid_before_utc

    restricciones = cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    usos = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert not restricciones.value.ca
    assert usos.value.digital_signature


def test_certificado_firmado_por_otra_ca(
    publica_usuario, tmp_path, monkeypatch
):
    """Una CA con el mismo nombre no sustituye la raíz confiable."""
    with monkeypatch.context() as otra_configuracion:
        otra_configuracion.setattr(
            pki, "CA_DIRECTORY", tmp_path / "otra_ca"
        )
        crear_ca_prueba(pki.CA_DIRECTORY, PASSWORD_CA_PRUEBA)
        datos = pki.emitir_certificado_usuario(
            "ana", publica_usuario, PASSWORD_CA_PRUEBA
        )

    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(datos, "ana")


def test_certificado_alterado(publica_usuario):
    """Cambiar el sujeto sin volver a firmar invalida el certificado."""
    datos = pki.emitir_certificado_usuario(
        "ana", publica_usuario, PASSWORD_CA_PRUEBA
    )
    cert = x509.load_pem_x509_certificate(datos.encode("ascii"))
    der = cert.public_bytes(serialization.Encoding.DER)

    # Localizamos el Common Name de tres letras dentro del certificado DER.
    patron = b"\x06\x03\x55\x04\x03\x0c\x03ana"
    assert der.count(patron) == 1

    # Conservamos la longitud y la firma original al cambiar ana por eva.
    der = der.replace(patron, patron[:-3] + b"eva")
    alterado = x509.load_der_x509_certificate(der)
    nombre = alterado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert nombre[0].value == "eva"

    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(
            alterado.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "eva"
        )


def test_certificado_de_otra_cuenta(publica_usuario):
    """Un certificado válido de ana no autentica la identidad de bob."""
    datos = pki.emitir_certificado_usuario(
        "ana", publica_usuario, PASSWORD_CA_PRUEBA
    )
    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(datos, "bob")


@pytest.mark.parametrize("estado", ["caducado", "prematuro"])
def test_rechazar_fuera_de_vigencia(publica_usuario, estado):
    """Rechaza certificados caducados o cuyo periodo todavía no empieza."""
    ahora = datetime.now(timezone.utc)

    if estado == "caducado":
        inicio = ahora - timedelta(minutes=4)
        fin = ahora - timedelta(minutes=1)
    else:
        inicio = ahora + timedelta(hours=1)
        fin = ahora + timedelta(days=30)

    datos = _crear_certificado_prueba(
        publica_usuario, inicio=inicio, fin=fin
    )
    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(datos, "ana")


@pytest.mark.parametrize(
    "perfil", ["sin_firma", "ca", "critica", "rsa", "sin_extensiones"]
)
def test_rechazar_perfil_inadecuado(publica_usuario, perfil):
    """Rechaza algoritmos, extensiones o permisos ajenos al perfil de firma."""
    datos = _crear_certificado_prueba(publica_usuario, perfil=perfil)
    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(datos, "ana")


@pytest.mark.parametrize("usuario", ["", "ab", " ana ", "x" * 31])
def test_rechazar_identidad_invalida(publica_usuario, usuario):
    """Una identidad no válida no puede obtener un certificado."""
    with pytest.raises(ValueError):
        pki.emitir_certificado_usuario(
            usuario, publica_usuario, PASSWORD_CA_PRUEBA
        )


@pytest.mark.parametrize("tipo", ["nulo", "ilegible", "duplicado"])
def test_rechazar_certificado_malformado(publica_usuario, tipo):
    """Solo se admite un certificado PEM interpretable por usuario."""
    datos = pki.emitir_certificado_usuario(
        "ana", publica_usuario, PASSWORD_CA_PRUEBA
    )

    if tipo == "nulo":
        datos = None
    elif tipo == "ilegible":
        datos = "Esto no es un certificado."
    else:
        datos = datos + datos

    with pytest.raises(ValueError):
        pki.validar_certificado_usuario(datos, "ana")


def test_validar_no_necesita_privada_ca(publica_usuario):
    """La verificación solo necesita la raíz pública, sin desbloquear la CA."""
    datos = pki.emitir_certificado_usuario(
        "ana", publica_usuario, PASSWORD_CA_PRUEBA
    )
    (pki.CA_DIRECTORY / "ca_key.pem").unlink()
    assert pki.validar_certificado_usuario(datos, "ana") == publica_usuario


def test_emision_rechaza_password_ca_incorrecta(publica_usuario):
    """La contraseña incorrecta de la CA impide emitir certificados."""
    with pytest.raises(ValueError):
        pki.emitir_certificado_usuario(
            "ana", publica_usuario, "Contraseña incorrecta"
        )


@pytest.mark.parametrize(
    "usuario", ["lucía", "usuario/dos", "ana+bob", "ana\\bob", "Ana María"]
)
def test_certificado_con_nombre_especial(publica_usuario, usuario):
    """Comprueba que se conserva exactamente la identidad del usuario."""
    certificado = pki.emitir_certificado_usuario(
        usuario, publica_usuario, PASSWORD_CA_PRUEBA
    )

    assert pki.validar_certificado_usuario(
        certificado, usuario
    ) == publica_usuario