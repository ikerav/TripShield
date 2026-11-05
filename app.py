"""Interfaz principal de TripShield desarrollada con Streamlit"""

import streamlit as st

from auth import hash_password, verify_password
from storage import guardar_usuario, buscar_usuario


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


def main():
    """gestiona la pantalla principal según el estado de autenticación"""

    st.title("✈️ TripShield")
    st.write("Comparte tus itinerarios de viaje de forma segura.")

    # mostramos el contenido privado solo si existe una sesión autenticada
    if "usuario" in st.session_state:
        st.success(f"Bienvenido, {st.session_state['usuario']}")

        st.write("Has iniciado sesión correctamente.")

        if st.button("Cerrar sesión"):
            # eliminamos el usuario de la sesión y volvemos a la pantalla de acceso
            del st.session_state["usuario"]
            st.rerun()

    else:
        # los usuarios no autenticados pueden registrarse o iniciar sesión
        tab_login, tab_registro = st.tabs([
            "Iniciar sesión", "Registrarse"
        ])

        with tab_login:
            mostrar_login()

        with tab_registro:
            mostrar_registro()


if __name__ == "__main__":
    main()