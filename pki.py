"""Emisión y validación de certificados X.509 de TripShield."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID, ExtensionOID

CA_DIRECTORY = Path(__file__).resolve().parent / "data" / "pki"

USER_VALIDITY_DAYS = 365

USO_FIRMA = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False
)


def _validar_nombre(usuario: str) -> None:
    """Comprueba que el identificador de usuario es válido."""
    if (
        not isinstance(usuario, str)
        or usuario != usuario.strip()
        or not 3 <= len(usuario) <= 30
        or not usuario.isprintable()
    ):
        raise ValueError("El usuario del certificado no es válido.")


def _verificar_certificado(
    certificado: x509.Certificate, raiz: x509.Certificate
) -> None:
    """Verifica la emisión directa y la vigencia del certificado."""
    certificado.verify_directly_issued_by(raiz)

    ahora = datetime.now(timezone.utc)

    if not certificado.not_valid_before_utc <= ahora < certificado.not_valid_after_utc:
        raise ValueError("El certificado no está vigente.")

    if certificado.version != x509.Version.v3:
        raise ValueError("Se esperaba un certificado X.509 v3.")

    # Solo admitimos las extensiones del perfil de TripShield.
    admitidas = {
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    }

    if any(ext.oid not in admitidas for ext in certificado.extensions):
        raise ValueError("El certificado contiene extensiones no admitidas.")

    ski = certificado.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    aki = certificado.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    )
    ski_raiz = raiz.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )

    if ski.critical or aki.critical or aki.value.key_identifier != ski_raiz.value.digest:
        raise ValueError("Los identificadores del certificado no son válidos.")


def cargar_certificado_ca() -> x509.Certificate:
    """Carga la raíz de confianza de la instalación."""
    try:
        certificados = x509.load_pem_x509_certificates(
            (CA_DIRECTORY / "ca_cert.pem").read_bytes()
        )

        if len(certificados) != 1:
            raise ValueError("Se esperaba un único certificado raíz.")

        raiz = certificados[0]
        restricciones = raiz.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usos = raiz.extensions.get_extension_for_class(x509.KeyUsage)

        if (
            not isinstance(raiz.public_key(), Ed25519PublicKey)
            or raiz.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
            or raiz.subject != raiz.issuer
            or not restricciones.critical
            or not restricciones.value.ca
            or restricciones.value.path_length != 0
            or not usos.critical
            or not usos.value.key_cert_sign
        ):
            raise ValueError("La raíz no cumple el perfil de TripShield.")

        _verificar_certificado(raiz, raiz)
        return raiz

    except (
        OSError, ValueError, TypeError, UnsupportedAlgorithm,
        InvalidSignature, x509.ExtensionNotFound,
        x509.DuplicateExtension, x509.InvalidVersion
    ) as error:
        raise ValueError("El certificado raíz no es válido.") from error


def emitir_certificado_usuario(
    usuario: str, publica: bytes, password_ca: str
) -> str:
    """Emite un certificado para la clave pública Ed25519 del usuario."""
    _validar_nombre(usuario)
    raiz = cargar_certificado_ca()

    if not isinstance(publica, bytes) or len(publica) != 32:
        raise ValueError("La clave pública Ed25519 debe tener 32 bytes.")

    if not isinstance(password_ca, str) or not password_ca:
        raise ValueError("La contraseña de la CA no es válida.")

    privada = serialization.load_pem_private_key(
        (CA_DIRECTORY / "ca_key.pem").read_bytes(),
        password=password_ca.encode("utf-8")
    )

    if (
        not isinstance(privada, Ed25519PrivateKey)
        or privada.public_key().public_bytes_raw()
        != raiz.public_key().public_bytes_raw()
    ):
        raise ValueError("La clave privada de la CA no corresponde a la raíz.")

    clave = Ed25519PublicKey.from_public_bytes(publica)
    ahora = datetime.now(timezone.utc)

    certificado = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, usuario)
        ]))
        .issuer_name(raiz.subject)
        .public_key(clave)
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora)
        .not_valid_after(min(
            ahora + timedelta(days=USER_VALIDITY_DAYS),
            raiz.not_valid_after_utc
        ))
        .add_extension(x509.BasicConstraints(False, None), critical=True)
        .add_extension(USO_FIRMA, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(clave), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                raiz.public_key()
            ), critical=False
        )
        .sign(privada, algorithm=None)
    )

    return certificado.public_bytes(serialization.Encoding.PEM).decode("ascii")


def validar_certificado_usuario(datos: str, usuario: str) -> bytes:
    """Valida el certificado y devuelve la clave pública certificada."""
    _validar_nombre(usuario)
    raiz = cargar_certificado_ca()

    try:
        if not isinstance(datos, str):
            raise ValueError("Se esperaba un certificado PEM.")

        certificados = x509.load_pem_x509_certificates(datos.encode("ascii"))

        if len(certificados) != 1:
            raise ValueError("Se esperaba un único certificado.")

        certificado = certificados[0]

        _verificar_certificado(certificado, raiz)

        publica = certificado.public_key()
        nombres = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        restricciones = certificado.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usos = certificado.extensions.get_extension_for_class(x509.KeyUsage)

        # Requisitos específicos de TripShield, no de X.509 en general.
        if (
            not isinstance(publica, Ed25519PublicKey)
            or certificado.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
            or certificado.issuer != raiz.subject
            or len(nombres) != 1
            or nombres[0].value != usuario
            or not restricciones.critical
            or restricciones.value.ca
            or not usos.critical
            or usos.value != USO_FIRMA
            or certificado.not_valid_before_utc < raiz.not_valid_before_utc
            or certificado.not_valid_after_utc > raiz.not_valid_after_utc
        ):
            raise ValueError("El certificado no cumple el perfil requerido.")

        return publica.public_bytes_raw()

    except (
        ValueError, TypeError, UnsupportedAlgorithm,
        InvalidSignature, x509.ExtensionNotFound,
        x509.DuplicateExtension, x509.InvalidVersion
    ) as error:
        raise ValueError("El certificado del usuario no es válido.") from error