"""Creación de autoridades certificadoras temporales para las pruebas."""

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


def crear_ca_prueba(directorio: Path, password: str) -> None:
    """Genera una CA de laboratorio mediante OpenSSL."""
    directorio.mkdir(mode=0o700)

    inicio = datetime.now(timezone.utc) - timedelta(days=1)

    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-newkey", "ed25519",
            "-keyout", str(directorio / "ca_key.pem"),
            "-out", str(directorio / "ca_cert.pem"),
            "-passout", "stdin",
            "-subj", "/O=TripShield/CN=TripShield Root CA",
            "-not_before", inicio.strftime("%Y%m%d%H%M%SZ"),
            "-days", "1825",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign"
        ],
        input=(password + "\n").encode("utf-8"),
        capture_output=True,
        check=True,
        timeout=15
    )