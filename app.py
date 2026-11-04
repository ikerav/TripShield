
import streamlit as st

st.set_page_config(
    page_title="TripShield",
    page_icon="✈️",
    layout="centered"
)

st.title("✈️ TripShield")

st.subheader("Viaja con tranquilidad")

st.write(
    "Organiza tus itinerarios y compártelos "
    "de forma segura con personas de confianza."
)

st.info("Bienvenido a TripShield")

if st.button("Comenzar"):
    st.success("¡La aplicación funciona correctamente!")
