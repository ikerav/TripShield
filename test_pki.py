"""Pruebas de generación de la CA y protección de su clave privada."""

from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

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