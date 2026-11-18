"""Configuración inicial de la CA y su contraseña local de TripShield."""

import os
import secrets
from pathlib import Path
from tempfile import NamedTemporaryFile

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pki


SECRETS_FILE = Path(__file__).resolve().parent / ".streamlit" / "secrets.toml"


def _guardar_configuracion(contenido: str) -> None:
    """Reemplaza la configuración de forma atómica y con permisos privados."""
    temporal = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=SECRETS_FILE.parent,
            prefix="secrets_", suffix=".tmp", delete=False
        ) as file:
            temporal = Path(file.name)
            file.write(contenido)
            file.flush()
            os.fsync(file.fileno())

        temporal.replace(SECRETS_FILE)
    finally:
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def configurar_ca() -> bool:
    """Configura la CA sin sustituir claves existentes; indica si se creó."""
    if not SECRETS_FILE.is_file():
        raise FileNotFoundError("Primero prepara .streamlit/secrets.toml.")

    # Un único proceso puede modificar a la vez la contraseña y la CA.
    bloqueo = SECRETS_FILE.with_name(".pki_setup.lock")
    descriptor = os.open(
        bloqueo, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    os.close(descriptor)

    try:
        contenido = SECRETS_FILE.read_text(encoding="utf-8")
        datos = tomllib.loads(contenido)
        maestra = datos.get("MASTER_PASSWORD")
        if not isinstance(maestra, str) or not maestra:
            raise ValueError("La contraseña maestra todavía no está configurada.")

        nueva_password = "CA_PASSWORD" not in datos
        if nueva_password:
            if pki.CA_DIRECTORY.exists():
                raise ValueError("Ya existe una CA sin su contraseña configurada.")
            password = secrets.token_urlsafe(32)
        else:
            password = datos["CA_PASSWORD"]

        if (
            not isinstance(password, str)
            or len(password) < 16
            or password == maestra
        ):
            raise ValueError("La contraseña de la CA no es válida o independiente.")

        if nueva_password:
            # Guardamos la contraseña antes de crear la privada que protegerá.
            # El prefijo añade una clave raíz TOML y conserva el texto anterior.
            _guardar_configuracion(f'CA_PASSWORD = "{password}"\n\n{contenido}')
        else:
            os.chmod(SECRETS_FILE, 0o600)

        if pki.CA_DIRECTORY.exists():
            pki.cargar_ca(password)
            return False

        pki.inicializar_ca(password)
        pki.cargar_ca(password)
        return True
    finally:
        bloqueo.unlink(missing_ok=True)


def main() -> None:
    """Prepara la CA y muestra únicamente el resultado, sin secretos."""
    try:
        creada = configurar_ca()
    except tomllib.TOMLDecodeError:
        raise SystemExit(
            "El archivo secrets.toml no tiene un formato válido."
        ) from None
    except FileExistsError:
        raise SystemExit(
            "Configuración ocupada o incompleta: revisa los archivos existentes."
        ) from None
    except (OSError, ValueError):
        raise SystemExit(
            "No se ha completado la configuración de la CA. "
            "Conserva los archivos y revisa la configuración antes de continuar."
        ) from None

    print("CA creada correctamente." if creada else "CA existente verificada.")
    print("Contraseña de la CA guardada en la configuración local.")
    print("Ubicación de la CA:", pki.CA_DIRECTORY)


if __name__ == "__main__":
    main()