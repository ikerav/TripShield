"""Interfaz principal de TripShield desarrollada con Streamlit"""

import streamlit as st

from auth import hash_password, verify_password
from storage import guardar_usuario, buscar_usuario

from datetime import time

from cryptography.exceptions import InvalidTag

from keys import cargar_clave_maestra
from trips import crear_viaje, listar_viajes


st.set_page_config(
    page_title="TripShield",
    page_icon="✈️",
    layout="centered"
)

def mostrar_registro():
    """muestra el formulario de registro y crea nuevos usuarios"""

    # El formulario recoge todos los datos antes de procesar el registro.
    with st.form("registro"):
        username = st.text_input("Nombre de usuario").strip()
        password = st.text_input("Contraseña", type="password")
        confirm_password = st.text_input(
            "Confirmar contraseña", type="password"
        )

        registrar = st.form_submit_button("Crear cuenta")

    if registrar:
        # Validamos los datos antes de realizar operaciones criptográficas.
        if not username or not password:
            st.error("Debes completar todos los campos.")
            return

        if not 3 <= len(username) <= 30:
            st.error("El usuario debe tener entre 3 y 30 caracteres.")
            return

        if len(password) < 8:
            st.error("La contraseña debe tener al menos 8 caracteres.")
            return

        if password != confirm_password:
            st.error("Las contraseñas no coinciden.")
            return

        try:
            # Generamos el hash Scrypt y su sal aleatoria, sin guardar la contraseña.
            password_data = hash_password(password)

            # Guardamos las credenciales y comprobamos que el usuario no exista.
            guardar_usuario(username, password_data)
            st.success("Cuenta creada correctamente. Ya puedes iniciar sesión.")

        except ValueError as e:
            # Capturamos los errores de registro para mostrarlos en la interfaz.
            st.error(str(e))


def mostrar_login():
    """Verifica las credenciales e inicia la sesión del usuario."""

    # El inicio de sesión se procesa únicamente al enviar el formulario.
    with st.form("login"):
        username = st.text_input("Nombre de usuario").strip()
        password = st.text_input("Contraseña", type="password")

        entrar = st.form_submit_button("Iniciar sesión")

    if entrar:
        # Recuperamos el hash y la sal del usuario para verificar su contraseña.
        usuario = buscar_usuario(username)

        # No revelamos si el error corresponde al usuario o a la contraseña.
        if usuario is None or not verify_password(password, usuario):
            st.error("Usuario o contraseña incorrectos.")
            return

        # Session State mantiene al usuario identificado entre ejecuciones
        st.session_state["usuario"] = username

        # Volvemos a ejecutar la aplicación para mostrar la pantalla privada.
        st.rerun()


def mostrar_nuevo_viaje(usuario: str, clave: bytes) -> None:
    """Permite crear un itinerario y almacenar sus etapas cifradas"""
    st.subheader("Nuevo viaje")

    num_etapas = st.number_input(
        "Número de etapas", min_value=1, max_value=5, value=1
    )

    with st.form("nuevo_viaje"):
        titulo = st.text_input("Nombre del viaje")
        etapas = []

        # Recogemos el destino y la llegada prevista de cada etapa.
        for i in range(num_etapas):
            st.markdown(f"**Etapa {i + 1}**")

            destino = st.text_input("Destino", key=f"destino_{i}")
            fecha = st.date_input("Fecha de llegada", key=f"fecha_{i}")
            hora = st.time_input(
                "Hora de llegada", value=time(12, 0), key=f"hora_{i}"
            )

            etapas.append({
                "destino": destino.strip(),
                "fecha": fecha.isoformat(),
                "hora": hora.strftime("%H:%M")
            })

        guardar = st.form_submit_button("Guardar viaje")

    if guardar:
        if not titulo.strip() or any(not e["destino"] for e in etapas):
            st.error("Debes indicar el nombre del viaje y todos los destinos.")
            return

        # La función crear_viaje cifra los datos antes de almacenarlos.
        crear_viaje(usuario, titulo, etapas, clave)
        st.rerun()


def mostrar_mis_viajes(usuario: str, clave: bytes) -> None:
    """Muestra los itinerarios que puede consultar el usuario."""
    st.subheader("Mis viajes")

    viajes = listar_viajes(usuario, clave)

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


def main():
    """gestiona la pantalla principal según el estado de autenticación"""

    st.title("✈️ TripShield")
    st.write("Comparte tus itinerarios de viaje de forma segura.")

    # mostramos el contenido privado solo si existe una sesión autenticada
    if "usuario" in st.session_state:
        usuario = st.session_state["usuario"]

        st.success(f"Bienvenido, {usuario}")

        if st.button("Cerrar sesión"):
            del st.session_state["usuario"]
            st.rerun()

        # Recuperamos la clave maestra solo después de autenticar al usuario.
        try:
            clave = cargar_clave_maestra(st.secrets["MASTER_PASSWORD"])
        except (InvalidTag, FileNotFoundError, KeyError, ValueError):
            st.error("No se ha podido recuperar la clave de cifrado.")
            st.stop()

        tab_viajes, tab_nuevo = st.tabs([
            "Mis viajes", "Nuevo viaje"
        ])

        with tab_viajes:
            mostrar_mis_viajes(usuario, clave)

        with tab_nuevo:
            mostrar_nuevo_viaje(usuario, clave)
    else:
        # Mostramos los formularios si no hay ningún usuario autenticado.
        tab_login, tab_registro = st.tabs([
            "Iniciar sesión", "Registrarse"
        ])

        with tab_login:
            mostrar_login()

        with tab_registro:
            mostrar_registro()


if __name__ == "__main__":
    main()