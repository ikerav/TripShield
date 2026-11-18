"""Autoridad de certificación privada de TripShield."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID, ExtensionOID


CA_VALIDITY_DAYS = 365 * 5
USER_VALIDITY_DAYS = 365
# La configuración del servidor permite separar la CA de cada instalación.
CA_DIRECTORY = Path(
    os.environ.get("TRIPSHIELD_CA_DIR")
    or str(Path.home() / ".tripshield" / "pki")
).expanduser()


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


def _validar_raiz_ca(certificado: x509.Certificate) -> None:
    """Comprueba la autofirma, vigencia y permisos de la raíz configurada."""
    if not isinstance(certificado, x509.Certificate):
        raise ValueError("El certificado de la CA no es válido.")

    try:
        publica = certificado.public_key()
        ahora = datetime.now(timezone.utc)
        if (
            not isinstance(publica, Ed25519PublicKey)
            or certificado.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
            or certificado.subject != certificado.issuer
            or not certificado.not_valid_before_utc <= ahora
            or not ahora < certificado.not_valid_after_utc
        ):
            raise ValueError("La raíz no cumple los requisitos de TripShield.")

        restricciones = certificado.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usos = certificado.extensions.get_extension_for_class(x509.KeyUsage)
        if (
            not restricciones.critical
            or not restricciones.value.ca
            or restricciones.value.path_length != 0
            or not usos.critical
            or not usos.value.key_cert_sign
        ):
            raise ValueError("La raíz no tiene permisos válidos de CA.")

        # Rechazamos extensiones críticas que la aplicación no sabe procesar.
        admitidas = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
        if any(
            extension.critical and extension.oid not in admitidas
            for extension in certificado.extensions
        ):
            raise ValueError("La raíz contiene una extensión crítica no admitida.")

        publica.verify(certificado.signature, certificado.tbs_certificate_bytes)
    except (
        InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound,
        x509.DuplicateExtension, TypeError, ValueError
    ) as error:
        raise ValueError("El certificado raíz de la CA no es válido.") from error


def _guardar_archivo_ca(ruta: Path, contenido: bytes) -> None:
    """Crea un archivo privado sin sobrescribir uno existente."""
    descriptor = os.open(
        ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "wb") as file:
        file.write(contenido)
        file.flush()
        os.fsync(file.fileno())


def inicializar_ca(password: str) -> None:
    """Crea y guarda una CA nueva únicamente si su directorio no existe."""
    privada, certificado = crear_ca()
    protegida = proteger_clave_ca(privada, password)
    certificado_pem = certificado.public_bytes(serialization.Encoding.PEM)

    CA_DIRECTORY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir sin exist_ok reserva el directorio e impide sustituir una CA anterior.
    CA_DIRECTORY.mkdir(mode=0o700)
    _guardar_archivo_ca(CA_DIRECTORY / "ca_key.pem", protegida)
    _guardar_archivo_ca(CA_DIRECTORY / "ca_cert.pem", certificado_pem)
    # Si una escritura falla, no regeneramos ni reparamos la CA automáticamente.


def cargar_certificado_ca() -> x509.Certificate:
    """Carga la raíz de confianza desde su ubicación local independiente."""
    datos = (CA_DIRECTORY / "ca_cert.pem").read_bytes()
    try:
        certificado = x509.load_pem_x509_certificate(datos)
    except ValueError as error:
        raise ValueError("El archivo del certificado raíz no es válido.") from error

    # La confianza procede de esta configuración, nunca del registro de usuarios.
    _validar_raiz_ca(certificado)
    return certificado


def cargar_ca(password: str) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    """Desbloquea la CA y comprueba que su privada corresponde al certificado."""
    certificado = cargar_certificado_ca()
    protegida = (CA_DIRECTORY / "ca_key.pem").read_bytes()
    privada = desbloquear_clave_ca(protegida, password)

    if (
        privada.public_key().public_bytes_raw()
        != certificado.public_key().public_bytes_raw()
    ):
        raise ValueError("La privada de la CA no corresponde al certificado raíz.")

    return privada, certificado


def _validar_nombre_certificado(usuario: str) -> None:
    """Exige un nombre de cuenta válido y sin espacios en los extremos."""
    if (
        not isinstance(usuario, str)
        or usuario != usuario.strip()
        or not 3 <= len(usuario) <= 30
    ):
        raise ValueError("El usuario del certificado no es válido.")


def emitir_certificado_usuario(
    usuario: str, publica: bytes, password_ca: str
) -> str:
    """Emite un certificado público de firma para la clave Ed25519 del usuario."""
    _validar_nombre_certificado(usuario)
    if not isinstance(publica, bytes) or len(publica) != 32:
        raise ValueError("La clave pública Ed25519 debe tener 32 bytes.")

    publica_usuario = Ed25519PublicKey.from_public_bytes(publica)
    privada_ca, raiz = cargar_ca(password_ca)
    ahora = datetime.now(timezone.utc)
    inicio = max(ahora - timedelta(minutes=5), raiz.not_valid_before_utc)
    fin = min(
        ahora + timedelta(days=USER_VALIDITY_DAYS), raiz.not_valid_after_utc
    )
    if fin <= ahora:
        raise ValueError("La CA ya no puede emitir certificados vigentes.")

    nombre = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TripShield"),
        x509.NameAttribute(NameOID.COMMON_NAME, usuario)
    ])
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(raiz.subject)
        .public_key(publica_usuario)
        .serial_number(x509.random_serial_number())
        # La vigencia del usuario no puede superar la de la CA emisora.
        .not_valid_before(inicio)
        .not_valid_after(fin)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(private_key=privada_ca, algorithm=None)
    )

    # El certificado es público y se representa como texto para guardarlo en JSON.
    return certificado.public_bytes(serialization.Encoding.PEM).decode("ascii")


def validar_certificado_usuario(datos: str, usuario: str) -> bytes:
    """Devuelve la pública solo si el certificado y su identidad son válidos."""
    _validar_nombre_certificado(usuario)
    if not isinstance(datos, str) or not datos.strip():
        raise ValueError("Debes proporcionar un certificado de usuario en PEM.")

    # La raíz se carga de la configuración local, no de los datos del usuario.
    raiz = cargar_certificado_ca()
    try:
        certificados = x509.load_pem_x509_certificates(datos.encode("ascii"))
        if len(certificados) != 1:
            raise ValueError("Se esperaba un único certificado de usuario.")

        certificado = certificados[0]
        publica = certificado.public_key()
        ahora = datetime.now(timezone.utc)
        if (
            certificado.version != x509.Version.v3
            or not isinstance(publica, Ed25519PublicKey)
            or certificado.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
            or certificado.issuer != raiz.subject
            or not certificado.not_valid_before_utc <= ahora
            or not ahora < certificado.not_valid_after_utc
            or certificado.not_valid_before_utc < raiz.not_valid_before_utc
            or certificado.not_valid_after_utc > raiz.not_valid_after_utc
        ):
            raise ValueError("El certificado no cumple los requisitos de TripShield.")

        nombres = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(nombres) != 1 or nombres[0].value != usuario:
            raise ValueError("El certificado pertenece a otra cuenta.")

        restricciones = certificado.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usos = certificado.extensions.get_extension_for_class(x509.KeyUsage)
        if (
            not restricciones.critical
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
            raise ValueError("El certificado no tiene los permisos de firma esperados.")

        admitidas = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
        if any(
            extension.critical and extension.oid not in admitidas
            for extension in certificado.extensions
        ):
            raise ValueError("El certificado tiene una extensión crítica no admitida.")

        # Coincidir en el texto del emisor no basta: comprobamos su firma.
        raiz.public_key().verify(
            certificado.signature, certificado.tbs_certificate_bytes
        )
        return publica.public_bytes_raw()

    except (
        InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound,
        x509.DuplicateExtension, TypeError, ValueError
    ) as error:
        raise ValueError("El certificado del usuario no es válido.") from error