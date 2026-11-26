"""Emisión y validación de certificados mediante OpenSSL."""

import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
from cryptography.exceptions import UnsupportedAlgorithm


USER_VALIDITY_DAYS = 365

CA_DIRECTORY = Path(
    os.environ.get("TRIPSHIELD_CA_DIR")
    or str(Path.home() / ".tripshield" / "pki-externa")
).expanduser()

EXTENSIONES_USUARIO = """\
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
"""


def _ejecutar_openssl(
    argumentos: list[str], entrada: bytes = b""
) -> None:
    """Ejecuta OpenSSL y rechaza las operaciones fallidas."""
    try:
        subprocess.run(
            ["openssl", *argumentos],
            input=entrada,
            capture_output=True,
            check=True,
            timeout=15
        )
    except (
        OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired
    ) as error:
        raise ValueError("La operación con OpenSSL ha fallado.") from error


def _validar_nombre_certificado(usuario: str) -> None:
    """Comprueba que el nombre representa una cuenta válida."""
    if (
        not isinstance(usuario, str)
        or usuario != usuario.strip()
        or not 3 <= len(usuario) <= 30
        or not usuario.isprintable()
        or not usuario.isascii()
    ):
        raise ValueError("El usuario del certificado no es válido.")


def cargar_certificado_ca() -> x509.Certificate:
    """Carga y verifica el certificado raíz configurado."""
    ruta = CA_DIRECTORY / "ca_cert.pem"

    try:
        certificados = x509.load_pem_x509_certificates(ruta.read_bytes())

        if len(certificados) != 1:
            raise ValueError("Se esperaba un único certificado raíz.")

        raiz = certificados[0]

        _ejecutar_openssl([
            "verify", "-x509_strict", "-check_ss_sig",
            "-trusted", str(ruta), str(ruta)
        ])

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
            raise ValueError("La raíz no cumple el perfil requerido.")

        return raiz

    except (
        OSError, ValueError, TypeError, UnsupportedAlgorithm,
        x509.ExtensionNotFound, x509.DuplicateExtension
    ) as error:
        raise ValueError("El certificado raíz no es válido.") from error

def emitir_certificado_usuario(
    usuario: str, publica: bytes, password_ca: str
) -> str:
    """Emite un certificado de usuario utilizando OpenSSL."""
    _validar_nombre_certificado(usuario)

    if not isinstance(publica, bytes) or len(publica) != 32:
        raise ValueError("La clave pública Ed25519 debe tener 32 bytes.")

    if (
        not isinstance(password_ca, str)
        or len(password_ca) < 16
        or "\n" in password_ca
        or "\r" in password_ca
        or "\x00" in password_ca
    ):
        raise ValueError("La contraseña de la CA no es válida.")

    raiz = cargar_certificado_ca()
    ahora = datetime.now(timezone.utc)
    fin = min(
        ahora + timedelta(days=USER_VALIDITY_DAYS),
        raiz.not_valid_after_utc
    )

    # Escapamos los caracteres especiales del nombre X.509.
    nombre = usuario.replace("\\", "\\\\")
    nombre = nombre.replace("/", "\\/").replace("+", "\\+")

    with TemporaryDirectory() as directorio:
        ruta = Path(directorio)

        publica_pem = Ed25519PublicKey.from_public_bytes(
            publica
        ).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        (ruta / "publica.pem").write_bytes(publica_pem)
        (ruta / "extensiones.cnf").write_text(
            EXTENSIONES_USUARIO, encoding="utf-8"
        )

        _ejecutar_openssl([
            "x509", "-new",
            "-force_pubkey", str(ruta / "publica.pem"),
            "-CA", str(CA_DIRECTORY / "ca_cert.pem"),
            "-CAkey", str(CA_DIRECTORY / "ca_key.pem"),
            "-passin", "stdin",
            "-subj", f"/O=TripShield/CN={nombre}",
            "-set_serial", hex(x509.random_serial_number()),
            "-not_after", fin.strftime("%Y%m%d%H%M%SZ"),
            "-extfile", str(ruta / "extensiones.cnf"),
            "-out", str(ruta / "certificado.pem")
        ], (password_ca + "\n").encode("utf-8"))

        certificado = (ruta / "certificado.pem").read_text(
            encoding="ascii"
        )

    if validar_certificado_usuario(certificado, usuario) != publica:
        raise ValueError("La clave certificada no coincide con la original.")

    return certificado


def validar_certificado_usuario(datos: str, usuario: str) -> bytes:
    """Valida el certificado y devuelve la clave pública certificada."""
    _validar_nombre_certificado(usuario)

    if not isinstance(datos, str) or not datos.strip():
        raise ValueError("Debes proporcionar un certificado PEM.")

    raiz = cargar_certificado_ca()

    try:
        certificados = x509.load_pem_x509_certificates(datos.encode("ascii"))

        if len(certificados) != 1:
            raise ValueError("Se esperaba un único certificado.")

        certificado = certificados[0]
        publica = certificado.public_key()

        nombres = certificado.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        restricciones = certificado.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usos = certificado.extensions.get_extension_for_class(x509.KeyUsage)

        # Comprobaciones específicas del perfil de usuario de TripShield.
        if (
            certificado.version != x509.Version.v3
            or not isinstance(publica, Ed25519PublicKey)
            or certificado.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
            or certificado.issuer != raiz.subject
            or len(nombres) != 1
            or nombres[0].value != usuario
            or certificado.not_valid_before_utc < raiz.not_valid_before_utc
            or certificado.not_valid_after_utc > raiz.not_valid_after_utc
            or not restricciones.critical
            or restricciones.value.ca
            or not usos.critical
            or not usos.value.digital_signature
            or usos.value.content_commitment
            or usos.value.key_encipherment
            or usos.value.data_encipherment
            or usos.value.key_agreement
            or usos.value.key_cert_sign
            or usos.value.crl_sign
        ):
            raise ValueError("El certificado no cumple el perfil requerido.")

        with TemporaryDirectory() as directorio:
            ruta = Path(directorio) / "certificado.pem"
            ruta.write_bytes(
                certificado.public_bytes(serialization.Encoding.PEM)
            )

            # OpenSSL verifica la cadena de confianza, la firma y la vigencia.
            _ejecutar_openssl([
                "verify", "-x509_strict", "-check_ss_sig",
                "-trusted", str(CA_DIRECTORY / "ca_cert.pem"),
                str(ruta)
            ])

        return publica.public_bytes_raw()

    except (
        ValueError, TypeError, x509.ExtensionNotFound,
        x509.DuplicateExtension
    ) as error:
        raise ValueError("El certificado del usuario no es válido.") from error