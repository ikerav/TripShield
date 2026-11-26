"""Pruebas de configuración inicial de la CA sin usar datos reales."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

import init_pki
import pki


MASTER_PRUEBA = "Contraseña maestra ficticia de pruebas 2026!"
CA_PRUEBA = "Contraseña independiente ficticia de CA 2026!"


@pytest.fixture
def configuracion(tmp_path, monkeypatch):
    """Aísla los secretos y la CA en carpetas temporales independientes."""
    carpeta = tmp_path / "proyecto" / ".streamlit"
    carpeta.mkdir(parents=True)
    ruta = carpeta / "secrets.toml"
    ruta.write_text(
        f'MASTER_PASSWORD = "{MASTER_PRUEBA}"\n'
        '# Comentario conservado\n[otra_seccion]\nvalor = "conservar"\n',
        encoding="utf-8"
    )
    monkeypatch.setattr(init_pki, "SECRETS_FILE", ruta)
    monkeypatch.setattr(pki, "CA_DIRECTORY", tmp_path / "estado_privado" / "pki")
    return ruta


def _leer_configuracion(ruta):
    """Lee únicamente la configuración ficticia preparada por las pruebas."""
    return init_pki.tomllib.loads(ruta.read_text(encoding="utf-8"))


def test_configurar_ca_conserva_configuracion(configuracion):
    """Genera una contraseña independiente y conserva la configuración previa."""
    original = configuracion.read_text(encoding="utf-8")
    assert init_pki.configurar_ca()

    datos = _leer_configuracion(configuracion)
    assert len(datos["CA_PASSWORD"]) >= 16
    assert datos["CA_PASSWORD"] != MASTER_PRUEBA
    assert datos["MASTER_PASSWORD"] == MASTER_PRUEBA
    assert datos["otra_seccion"]["valor"] == "conservar"
    assert configuracion.read_text(encoding="utf-8").endswith(original)

    pki.cargar_ca(datos["CA_PASSWORD"])
    if os.name == "posix":
        assert stat.S_IMODE(configuracion.stat().st_mode) == 0o600

    assert not configuracion.with_name(".pki_setup.lock").exists()


def test_repetir_configuracion_no_rota_ca(configuracion):
    """Repetir el comando conserva tanto la contraseña como el par de la CA."""
    init_pki.configurar_ca()
    originales = {
        p.name: p.read_bytes() for p in pki.CA_DIRECTORY.iterdir()
    }
    secretos = configuracion.read_bytes()

    assert not init_pki.configurar_ca()
    assert configuracion.read_bytes() == secretos

    actuales = {
        p.name: p.read_bytes() for p in pki.CA_DIRECTORY.iterdir()
    }
    assert actuales == originales


def test_ca_sin_password_no_se_reemplaza(configuracion):
    """Una CA existente sin contraseña configurada exige revisión manual."""
    pki.inicializar_ca(CA_PRUEBA)
    secretos = configuracion.read_bytes()
    original = (pki.CA_DIRECTORY / "ca_key.pem").read_bytes()

    with pytest.raises(ValueError):
        init_pki.configurar_ca()

    assert configuracion.read_bytes() == secretos
    assert (pki.CA_DIRECTORY / "ca_key.pem").read_bytes() == original


def test_reutilizar_password_configurada(configuracion):
    """Una contraseña válida ya configurada se reutiliza sin reescribirla."""
    contenido = configuracion.read_text(encoding="utf-8")
    configuracion.write_text(
        f'CA_PASSWORD = "{CA_PRUEBA}"\n' + contenido, encoding="utf-8"
    )
    original = configuracion.read_bytes()

    assert init_pki.configurar_ca()
    assert configuracion.read_bytes() == original

    pki.cargar_ca(CA_PRUEBA)
    if os.name == "posix":
        assert stat.S_IMODE(configuracion.stat().st_mode) == 0o600


@pytest.mark.parametrize("contenido", ["TOML = [", 'OTRO = "sin master"'])
def test_configuracion_invalida_no_crea_ca(configuracion, contenido):
    """Un TOML inválido o la ausencia de contraseña maestra detienen el proceso."""
    configuracion.write_text(contenido, encoding="utf-8")

    with pytest.raises(ValueError):
        init_pki.configurar_ca()

    assert not pki.CA_DIRECTORY.exists()
    assert configuracion.read_text(encoding="utf-8") == contenido
    assert not configuracion.with_name(".pki_setup.lock").exists()


@pytest.mark.parametrize("password", [123, "corta", MASTER_PRUEBA])
def test_rechazar_password_ca_invalida(configuracion, password):
    """Rechaza una contraseña corta, mal tipada o igual a la maestra."""
    valor = str(password) if isinstance(password, int) else f'"{password}"'
    contenido = configuracion.read_text(encoding="utf-8")
    configuracion.write_text(
        f'CA_PASSWORD = {valor}\n' + contenido, encoding="utf-8"
    )
    original = configuracion.read_bytes()

    with pytest.raises(ValueError):
        init_pki.configurar_ca()

    assert not pki.CA_DIRECTORY.exists()
    assert configuracion.read_bytes() == original


def test_password_existente_incorrecta_no_cambia_ca(configuracion):
    """Una contraseña equivocada no provoca una sustitución de la CA."""
    pki.inicializar_ca(CA_PRUEBA)
    contenido = configuracion.read_text(encoding="utf-8")
    configuracion.write_text(
        'CA_PASSWORD = "Otra contraseña de CA 2026!"\n' + contenido,
        encoding="utf-8"
    )
    secretos = configuracion.read_bytes()
    original = (pki.CA_DIRECTORY / "ca_key.pem").read_bytes()

    with pytest.raises(ValueError):
        init_pki.configurar_ca()

    assert configuracion.read_bytes() == secretos
    assert (pki.CA_DIRECTORY / "ca_key.pem").read_bytes() == original


def test_configuracion_simultanea_conserva_password_correcta(configuracion):
    """Dos ejecuciones no pueden guardar contraseñas distintas para la misma CA."""
    inicio = Barrier(2)

    def configurar():
        inicio.wait(timeout=5)
        try:
            return init_pki.configurar_ca()
        except FileExistsError:
            return "ocupada"

    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(lambda _: configurar(), range(2)))

    assert sum(r is True for r in resultados) == 1
    assert all(r is True or r is False or r == "ocupada" for r in resultados)
    pki.cargar_ca(_leer_configuracion(configuracion)["CA_PASSWORD"])
    assert not configuracion.with_name(".pki_setup.lock").exists()


def test_error_guardando_configuracion_no_crea_ca(configuracion, monkeypatch):
    """Si no se puede guardar la contraseña, la CA no llega a crearse."""
    original = configuracion.read_bytes()

    def fallar(contenido):
        raise OSError("Fallo de escritura ficticio")

    monkeypatch.setattr(init_pki, "_guardar_configuracion", fallar)
    with pytest.raises(OSError):
        init_pki.configurar_ca()

    assert not pki.CA_DIRECTORY.exists()
    assert configuracion.read_bytes() == original
    assert not configuracion.with_name(".pki_setup.lock").exists()


def test_error_creando_ca_conserva_password_y_privada(configuracion, monkeypatch):
    """Un fallo parcial conserva la privada cifrada y su contraseña de protección."""
    guardar = pki._guardar_archivo_ca

    def fallar_certificado(ruta, contenido):
        if ruta.name == "ca_cert.pem":
            raise OSError("Fallo de escritura ficticio")
        guardar(ruta, contenido)

    monkeypatch.setattr(pki, "_guardar_archivo_ca", fallar_certificado)
    with pytest.raises(OSError):
        init_pki.configurar_ca()

    password = _leer_configuracion(configuracion)["CA_PASSWORD"]
    privada = (pki.CA_DIRECTORY / "ca_key.pem").read_bytes()
    pki.desbloquear_clave_ca(privada, password)

    with pytest.raises(FileNotFoundError):
        init_pki.configurar_ca()

    assert _leer_configuracion(configuracion)["CA_PASSWORD"] == password
    assert (pki.CA_DIRECTORY / "ca_key.pem").read_bytes() == privada
    assert not configuracion.with_name(".pki_setup.lock").exists()