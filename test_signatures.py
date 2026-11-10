"""Pruebas de claves Ed25519 y firmas de llegada."""

import pytest

from cryptography.exceptions import InvalidTag

from signatures import (
    generar_claves_firma,
    proteger_clave_privada,
    desbloquear_clave_privada,
    firmar_confirmacion,
    verificar_confirmacion
)


PASSWORD_PRUEBA = "Clave ficticia para pruebas 2026"
USUARIO_PRUEBA = "viajero_prueba"


def test_generar_y_desbloquear_clave_privada():
    """Comprueba los tamaños y la recuperación de la clave privada original."""
    privada, publica = generar_claves_firma()
    protegida = proteger_clave_privada(
        privada, PASSWORD_PRUEBA, USUARIO_PRUEBA
    )
    recuperada = desbloquear_clave_privada(
        protegida, PASSWORD_PRUEBA, USUARIO_PRUEBA
    )

    assert len(privada) == 32
    assert len(publica) == 32
    assert recuperada == privada


@pytest.mark.parametrize(
    "password, usuario",
    [
        ("Contraseña incorrecta", USUARIO_PRUEBA),
        (PASSWORD_PRUEBA, "otro_usuario")
    ]
)
def test_rechazar_password_o_usuario_incorrectos(password, usuario):
    """Comprueba que la clave solo se desbloquea con sus datos correctos."""
    privada, _ = generar_claves_firma()
    protegida = proteger_clave_privada(
        privada, PASSWORD_PRUEBA, USUARIO_PRUEBA
    )

    with pytest.raises(InvalidTag):
        desbloquear_clave_privada(protegida, password, usuario)


@pytest.mark.parametrize("campo", ["salt", "nonce", "cifrado"])
def test_rechazar_clave_privada_manipulada(campo):
    """Comprueba el rechazo de modificaciones en los campos protegidos."""
    privada, _ = generar_claves_firma()
    protegida = proteger_clave_privada(
        privada, PASSWORD_PRUEBA, USUARIO_PRUEBA
    )

    # Alteramos un bit del campo seleccionado en una copia del registro.
    alterada = protegida.copy()
    contenido = bytearray.fromhex(alterada[campo])
    contenido[0] ^= 1
    alterada[campo] = contenido.hex()

    with pytest.raises(InvalidTag):
        desbloquear_clave_privada(
            alterada, PASSWORD_PRUEBA, USUARIO_PRUEBA
        )


@pytest.fixture
def confirmacion_prueba():
    """Proporciona una declaración de llegada ficticia para cada prueba."""
    return {
        "version": 1,
        "viaje_id": "viaje_prueba",
        "etapa_indice": 0,
        "propietario": USUARIO_PRUEBA,
        "etapa": {
            "destino": "Aeropuerto de Berlín",
            "fecha": "2026-11-15",
            "hora": "12:30"
        },
        "confirmado_en": "2026-11-15T11:32:00+00:00"
    }


def test_firmar_y_verificar_confirmacion(confirmacion_prueba):
    """Comprueba la firma original y su independencia del orden de campos."""
    privada, publica = generar_claves_firma()
    firma = firmar_confirmacion(confirmacion_prueba, privada)

    assert len(firma) == 64
    assert verificar_confirmacion(confirmacion_prueba, firma, publica)

    reordenada = dict(reversed(list(confirmacion_prueba.items())))
    assert verificar_confirmacion(reordenada, firma, publica)


@pytest.mark.parametrize(
    "campo, valor",
    [
        ("viaje_id", "otro_viaje"),
        ("etapa_indice", 1),
        ("propietario", "otro_usuario"),
        ("etapa", {"destino": "Otro destino"}),
        ("confirmado_en", "2026-11-15T12:00:00+00:00")
    ]
)
def test_rechazar_confirmacion_modificada(confirmacion_prueba, campo, valor):
    """Comprueba que cambiar el contenido firmado invalida la firma."""
    privada, publica = generar_claves_firma()
    firma = firmar_confirmacion(confirmacion_prueba, privada)

    alterada = confirmacion_prueba.copy()
    alterada[campo] = valor

    assert not verificar_confirmacion(alterada, firma, publica)


def test_rechazar_firma_modificada(confirmacion_prueba):
    """Comprueba el rechazo de una modificación en los bytes de la firma."""
    privada, publica = generar_claves_firma()
    firma = firmar_confirmacion(confirmacion_prueba, privada)

    # Cambiamos un bit de la firma y conservamos intacto el mensaje.
    alterada = bytearray(firma)
    alterada[0] ^= 1

    assert not verificar_confirmacion(
        confirmacion_prueba, bytes(alterada), publica
    )


def test_rechazar_clave_publica_incorrecta(confirmacion_prueba):
    """Comprueba que otra clave pública no valida la firma del viajero."""
    privada, _ = generar_claves_firma()
    _, otra_publica = generar_claves_firma()
    firma = firmar_confirmacion(confirmacion_prueba, privada)

    assert not verificar_confirmacion(confirmacion_prueba, firma, otra_publica)