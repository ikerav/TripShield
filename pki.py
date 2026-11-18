"""Autoridad de certificación privada de TripShield."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID


CA_VALIDITY_DAYS = 365 * 5


def crear_ca() -> tuple[Ed25519PrivateKey, x509.Certificate]:
    """Genera la clave Ed25519 y el certificado raíz autofirmado de la CA."""
    privada = Ed25519PrivateKey.generate()
    ahora = datetime.now(timezone.utc)
    nombre = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TripShield"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TripShield Root CA")
    ])

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(privada.public_key())
        .serial_number(x509.random_serial_number())
        # Un margen pequeño permite diferencias de reloj durante la creación.
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=CA_VALIDITY_DAYS))
        # Esta raíz solo emitirá certificados finales, sin CA intermedias.
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Ed25519 define internamente su hash; la API requiere algorithm=None.
        .sign(private_key=privada, algorithm=None)
    )

    return privada, certificado


def proteger_clave_ca(privada: Ed25519PrivateKey, password: str) -> bytes:
    """Codifica la privada de la CA como PEM PKCS8 cifrado con contraseña."""
    if not isinstance(privada, Ed25519PrivateKey):
        raise ValueError("La clave de la CA debe ser Ed25519.")

    if not isinstance(password, str) or len(password) < 16:
        raise ValueError(
            "La contraseña de la CA debe tener al menos 16 caracteres."
        )

    # La contraseña de la CA será independiente de la clave maestra y usuarios.
    return privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )


def desbloquear_clave_ca(datos: bytes, password: str) -> Ed25519PrivateKey:
    """Recupera una privada Ed25519 protegida o rechaza el contenido."""
    if not isinstance(datos, bytes) or not datos:
        raise ValueError("La clave cifrada de la CA debe contener datos PEM.")

    if not isinstance(password, str) or not password:
        raise ValueError("Debes indicar la contraseña de la CA.")

    try:
        privada = serialization.load_pem_private_key(
            datos, password=password.encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "No se puede desbloquear la clave de la CA."
        ) from error

    if not isinstance(privada, Ed25519PrivateKey):
        raise ValueError("La clave de la CA debe ser Ed25519.")

    return privada