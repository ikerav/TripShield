"""Configuración inicial de una instalación de TripShield."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from keys import MASTER_KEY_FILE, crear_clave_maestra
from pki import CA_DIRECTORY, cargar_certificado_ca


SECRETS_FILE = Path(__file__).resolve().parent / ".streamlit/secrets.toml"


def _guardar_archivo(ruta: Path, contenido: bytes) -> None:
    """Guarda un archivo con permisos privados y sin sobrescribirlo."""
    descriptor = os.open(
        ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )

    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(contenido)


def crear_ca(directorio: Path, password: str) -> None:
    """Genera una CA Ed25519 con su clave privada protegida."""
    privada = Ed25519PrivateKey.generate()
    publica = privada.public_key()

    nombre = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "TripShield Root CA")
    ])

    ahora = datetime.now(timezone.utc)

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(publica)
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(True, 0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                False, False, False, False, False,
                True, False, False, False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(publica),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(publica),
            critical=False
        )
        .sign(privada, algorithm=None)
    )

    directorio.mkdir(mode=0o700, parents=True)

    _guardar_archivo(
        directorio / "ca_key.pem",
        privada.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode())
        )
    )

    _guardar_archivo(
        directorio / "ca_cert.pem",
        certificado.public_bytes(serialization.Encoding.PEM)
    )


def main() -> None:
    """Prepara las claves y los secretos de una instalación nueva."""
    if (
        CA_DIRECTORY.exists()
        or SECRETS_FILE.exists()
        or MASTER_KEY_FILE.exists()
        or (MASTER_KEY_FILE.parent / "users.json").exists()
        or (MASTER_KEY_FILE.parent / "trips.json").exists()
    ):
        raise SystemExit("Ya existe una instalación. No se sobrescribirá.")

    password_ca = secrets.token_urlsafe(32)
    password_maestra = secrets.token_urlsafe(32)

    crear_ca(CA_DIRECTORY, password_ca)
    cargar_certificado_ca()

    SECRETS_FILE.parent.mkdir(mode=0o700, exist_ok=True)

    contenido = (
        f'MASTER_PASSWORD = "{password_maestra}"\n'
        f'CA_PASSWORD = "{password_ca}"\n'
    )

    _guardar_archivo(SECRETS_FILE, contenido.encode("utf-8"))
    crear_clave_maestra(password_maestra)

    print("TripShield configurado correctamente.")


if __name__ == "__main__":
    main()