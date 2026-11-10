"""Interfaz principal de TripShield desarrollada con Streamlit."""

from datetime import time

import streamlit as st
from cryptography.exceptions import InvalidTag

from auth import registrar_usuario, autenticar_usuario
from keys import cargar_clave_maestra
from trips import crear_viaje, listar_viajes, compartir_viaje


st.set_page_config(
    page_title="TripShield",
    page_icon="✈️",
    layout="centered"
)


def validar_registro(username: str, password: str, confirm_password: str) -> str | None:
    """Valida los datos de registro y devuelve un error si lo hay."""
    if not username or not password:
        return "Debes completar todos los campos."

    if not 3 <= len(username) <= 30:
        return "El usuario debe tener entre 3 y 30 caracteres."

    if len(password) < 8:
        return "La contraseña debe tener al menos 8 caracteres."

    if password != confirm_password:
        return "Las contraseñas no coinciden."

    return None


def mostrar_registro() -> None:
    """Muestra el formulario y registra la cuenta con sus claves de firma."""
    with st.form("registro"):
        username = st.text_input("Nombre de usuario").strip()
        password = st.text_input("Contraseña", type="password")
        confirm_password = st.text_input("Confirmar contraseña", type="password")
        registrar = st.form_submit_button("Crear cuenta")

    if not registrar:
        return

    error = validar_registro(username, password, confirm_password)
    if error:
        st.error(error)
        return

    try:
        registrar_usuario(username, password)
    except ValueError as error:
        st.error(str(error))
    except OSError:
        st.error("No se ha podido guardar la cuenta. Inténtalo de nuevo.")
    else:
        st.success("Cuenta creada correctamente. Ya puedes iniciar sesión.")


def mostrar_login() -> None:
    """Autentica al usuario y prepara las claves de las cuentas antiguas."""
    with st.form("login"):
        username = st.text_input("Nombre de usuario").strip()
        password = st.text_input("Contraseña", type="password")
        entrar = st.form_submit_button("Iniciar sesión")

    if not entrar:
        return

    try:
        valido = autenticar_usuario(username, password)
    except (OSError, ValueError, KeyError, TypeError):
        st.error("No se ha podido acceder a los datos de la cuenta.")
        return

    if not valido:
        st.error("Usuario o contraseña incorrectos.")
        return

    # Conservamos solo el usuario autenticado en el estado de la aplicación.
    st.session_state["usuario"] = username
    st.rerun()


def recoger_etapa(indice: int) -> dict:
    """Muestra los campos de una etapa y devuelve sus datos."""
    st.markdown(f"**Etapa {indice + 1}**")

    destino = st.text_input("Destino", key=f"destino_{indice}")
    fecha = st.date_input("Fecha de llegada", key=f"fecha_{indice}")
    hora = st.time_input(
        "Hora de llegada", value=time(12, 0), key=f"hora_{indice}"
    )

    # Convertimos fechas y horas a texto para almacenarlas en JSON.
    return {
        "destino": destino.strip(),
        "fecha": fecha.isoformat(),
        "hora": hora.strftime("%H:%M")
    }


def mostrar_nuevo_viaje(usuario: str, clave: bytes) -> None:
    """Permite crear un itinerario y almacenar sus etapas cifradas."""
    st.subheader("Nuevo viaje")

    num_etapas = st.number_input(
        "Número de etapas", min_value=1, max_value=5, value=1
    )

    with st.form("nuevo_viaje"):
        titulo = st.text_input("Nombre del viaje")

        etapas = []
        for i in range(num_etapas):
            etapas.append(recoger_etapa(i))

        guardar = st.form_submit_button("Guardar viaje")

    if guardar:
        if not titulo.strip() or any(not e["destino"] for e in etapas):
            st.error("Debes indicar el nombre del viaje y todos los destinos.")
            return

        # crear_viaje() cifra el itinerario antes de guardarlo.
        try:
            crear_viaje(usuario, titulo, etapas, clave)
        except (ValueError, OSError):
            st.error("No se ha podido guardar el viaje.")
            return

        # Mostramos el aviso después de recargar la pantalla.
        st.session_state["aviso_viaje"] = "Viaje guardado correctamente."
        st.rerun()


def mostrar_comparticion(viaje: dict, usuario: str, clave: bytes) -> None:
    """Permite al propietario compartir el viaje con un contacto de confianza."""
    if viaje["propietario"] != usuario:
        st.caption(f"Compartido contigo por {viaje['propietario']}.")
        return

    if viaje["contacto"] is not None:
        st.caption(f"Contacto de confianza: {viaje['contacto']}")
        return

    with st.form(f"compartir_{viaje['id']}"):
        contacto = st.text_input(
            "Usuario del contacto de confianza",
            key=f"contacto_{viaje['id']}"
        )
        compartir = st.form_submit_button("Compartir viaje")

    if not compartir:
        return

    try:
        compartir_viaje(viaje["id"], usuario, contacto, clave)
    except ValueError as error:
        st.error(str(error))
    except OSError: # si falla el almacenamiento
        st.error("No se ha podido guardar la compartición.")
    else:
        st.rerun()


def mostrar_mis_viajes(usuario: str, clave: bytes) -> None:
    """Muestra los itinerarios que puede consultar el usuario."""
    st.subheader("Mis viajes")

    try:
        viajes = listar_viajes(usuario, clave)
    except InvalidTag:
        st.error("No se puede verificar la integridad de los viajes almacenados.")
        return

    if not viajes:
        st.info("Todavía no tienes viajes registrados.")
        return

    for viaje in viajes:
        with st.expander(viaje["titulo"]):
            for i, etapa in enumerate(viaje["etapas"], start=1):
                st.write(
                    f"**Etapa {i}: {etapa['destino']}**"
                )
                st.write(
                    f"Llegada prevista: {etapa['fecha']} "
                    f"a las {etapa['hora']}"
                )

            mostrar_comparticion(viaje, usuario, clave)


def mostrar_area_privada(usuario: str) -> None:
    """Muestra las funcionalidades disponibles para el usuario autenticado"""
    st.success(f"Bienvenido, {usuario}")

    if st.button("Cerrar sesión"):
        del st.session_state["usuario"]
        st.rerun()

    # Recuperamos la clave maestra necesaria para gestionar los itinerarios.
    try:
        clave = cargar_clave_maestra(st.secrets["MASTER_PASSWORD"])
    except (InvalidTag, FileNotFoundError, KeyError, ValueError):
        st.error("No se ha podido recuperar la clave de cifrado.")
        st.stop()

    # Mostramos una sola vez la confirmación del último guardado.
    aviso = st.session_state.pop("aviso_viaje", None)
    if aviso:
        st.success(aviso)

    tab_viajes, tab_nuevo = st.tabs(["Mis viajes", "Nuevo viaje"])

    with tab_viajes:
        mostrar_mis_viajes(usuario, clave)

    with tab_nuevo:
        mostrar_nuevo_viaje(usuario, clave)


def main() -> None:
    """Muestra la interfaz según el estado de autenticación del usuario"""
    st.title("✈️ TripShield")
    st.write("Comparte tus itinerarios de viaje de forma segura.")

    if "usuario" in st.session_state:
        mostrar_area_privada(st.session_state["usuario"])

    else:
        tab_login, tab_registro = st.tabs([
            "Iniciar sesión", "Registrarse"
        ])

        with tab_login:
            mostrar_login()

        with tab_registro:
            mostrar_registro()


if __name__ == "__main__":
    main()