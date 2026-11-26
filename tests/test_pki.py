"""Pruebas de integración con la autoridad de certificación."""

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import pki
from signatures import generar_claves_firma
from setup_local import crear_ca as crear_ca_prueba


PASSWORD_CA = "Contraseña ficticia de CA para pruebas 2026!"


@pytest.fixture
def directorio_ca(tmp_path, monkeypatch):
    """Prepara una CA temporal sin modificar la instalación real."""
    ruta = tmp_path / "pki"
    monkeypatch.setattr(pki, "CA_DIRECTORY", ruta)
    crear_ca_prueba(ruta, PASSWORD_CA)
    return ruta


def test_cargar_raiz_valida(directorio_ca):
    """Comprueba que se acepta la raíz configurada."""
    raiz = pki.cargar_certificado_ca()

    assert isinstance(raiz.public_key(), Ed25519PublicKey)
    assert raiz.subject == raiz.issuer

    restricciones = raiz.extensions.get_extension_for_class(
        x509.BasicConstraints
    )

    assert restricciones.critical
    assert restricciones.value.ca
    assert restricciones.value.path_length == 0


@pytest.mark.parametrize("alteracion", ["pem_invalido", "firma_alterada"])
def test_rechazar_raiz_manipulada(directorio_ca, alteracion):
    """Comprueba que una raíz dañada o manipulada se rechaza."""
    ruta = directorio_ca / "ca_cert.pem"

    if alteracion == "pem_invalido":
        ruta.write_text("Certificado inválido", encoding="utf-8")
    else:
        raiz = pki.cargar_certificado_ca()

        der = bytearray(raiz.public_bytes(serialization.Encoding.DER))

        # Alteramos un bit de la autofirma.
        der[-1] ^= 1

        alterada = x509.load_der_x509_certificate(bytes(der))
        ruta.write_bytes(
            alterada.public_bytes(serialization.Encoding.PEM)
        )

    with pytest.raises(ValueError):
        pki.cargar_certificado_ca()


def test_rechazar_raiz_ausente(directorio_ca):
    """No se permite verificar sin una autoridad de confianza."""
    (directorio_ca / "ca_cert.pem").unlink()

    with pytest.raises(ValueError):
        pki.cargar_certificado_ca()


def test_rechazar_privada_de_otra_ca(directorio_ca, tmp_path):
    """Impide emitir certificados con claves de otra CA."""
    otra_ca = tmp_path / "otra_ca"
    crear_ca_prueba(otra_ca, PASSWORD_CA)

    (directorio_ca / "ca_key.pem").write_bytes(
        (otra_ca / "ca_key.pem").read_bytes()
    )

    _, publica = generar_claves_firma()

    with pytest.raises(ValueError):
        pki.emitir_certificado_usuario(
            "viajero", publica, PASSWORD_CA
        )


def test_rechazar_password_ca_incorrecta(directorio_ca):
    """Una contraseña incorrecta impide emitir certificados."""
    _, publica = generar_claves_firma()

    with pytest.raises(ValueError):
        pki.emitir_certificado_usuario(
            "viajero", publica, "Contraseña incorrecta de prueba"
        )


def test_emision_conserva_archivos_ca(directorio_ca):
    """La emisión de certificados no modifica la CA."""
    privada = directorio_ca / "ca_key.pem"
    certificado = directorio_ca / "ca_cert.pem"

    privada_original = privada.read_bytes()
    certificado_original = certificado.read_bytes()

    _, publica = generar_claves_firma()

    pki.emitir_certificado_usuario("viajero", publica, PASSWORD_CA)

    assert privada.read_bytes() == privada_original
    assert certificado.read_bytes() == certificado_original