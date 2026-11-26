"""Estilos y cabecera de viaje para la interfaz de TripShield."""

import streamlit as st


ESTILOS = """
<style>
.stApp {
    background: #fbf8f2;
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] {
    max-width: 980px;
    padding-top: 2.6rem;
    padding-bottom: 2rem;
}
.ts-brand {
    display: flex; align-items: center; justify-content: space-between;
    gap: 12px; margin: 0 0 22px;
}
.ts-wordmark { color: #3f5141; font-size: 25px; font-weight: 700; }
.ts-wordmark span { color: #789081; font-weight: 400; }
.ts-note {
    color: #68786d; font-size: 11px; letter-spacing: 1.5px;
    text-transform: uppercase;
}
.ts-hero {
    display: grid; grid-template-columns: 1.6fr 1fr; align-items: center;
    gap: 28px; padding: 30px 34px; margin-bottom: 22px;
    border: 1px solid #e8dfd9; border-radius: 28px;
    background: #f0f0e6;
    box-shadow: none;
}
.ts-eyebrow {
    color: #65785e; font-size: 11px; font-weight: 700; letter-spacing: 2px;
    margin-bottom: 12px;
}
.ts-hero h1 {
    color: #3f5141; font-family: Georgia, "Times New Roman", serif;
    font-size: clamp(29px, 4vw, 43px); font-weight: 500;
    line-height: 1.13; padding: 0; margin: 0 0 14px;
    letter-spacing: -1.2px;
}
.ts-hero h1 em { color: #7c8467; font-weight: 400; }
.ts-hero p {
    color: #59665e; font-size: 14px; line-height: 1.65;
    margin: 0; max-width: 340px;
}
.ts-ticket {
    transform: rotate(3deg); border: 1px solid #dedbd0; border-radius: 16px;
    background: #fffdf6; padding: 18px 20px;
    box-shadow: 3px 5px 0 #e0dfd4;
}
.ts-ticket-top { color: #7a806e; font-size: 10px; letter-spacing: 1.6px; }
.ts-route { display: flex; align-items: center; justify-content: space-between;
    color: #385f52; font-size: 25px; font-weight: 650; padding: 14px 0 10px; }
.ts-flight { color: #989f88; font-size: 23px; padding: 0 12px; }
.ts-ticket-bottom {
    border-top: 1px dashed #d9d2dc; padding-top: 11px;
    color: #6c766f; font-size: 11px; line-height: 1.6;
}
.ts-ticket-bottom strong { color: #556f60; }
[data-testid="stForm"] {
    border: 1px solid #e5e5da; border-radius: 22px;
    padding: 24px; background: #ffffffd9;
    box-shadow: 0 6px 20px #52634c06;
}
[data-testid="stExpander"] {
    border: 1px solid #dfdfd2; border-radius: 20px;
    background: #ffffffbf; box-shadow: 0 5px 18px #52634c05;
}
[data-testid="stMetric"] {
    border-radius: 18px; background: #ffffffb3; border-color: #e3e3d7;
}
[data-testid="stMetricValue"] { color: #386b5c; }
[data-testid="stTabs"] [role="tablist"] {
    gap: 8px; padding: 6px; border-radius: 18px;
    background: #eeeee5; margin: 8px 0 16px;
}
[data-testid="stTabs"] [role="tab"] {
    height: 42px; padding: 0 18px; border-radius: 13px;
    color: #5c6c61;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    background: #fffdf6; color: #315b4f;
    box-shadow: 0 2px 7px #52634c12;
}
[data-baseweb="tab-highlight"], [data-baseweb="tab-border"] { display: none; }
[data-testid="stAlert"] { border-radius: 16px; }
@media (max-width: 650px) {
    [data-testid="stMainBlockContainer"] { padding-top: 1.5rem; }
    .ts-note { display: none; }
    .ts-hero { grid-template-columns: 1fr; padding: 25px; gap: 24px; }
    .ts-ticket { transform: rotate(2deg); max-width: 290px; }
    [data-testid="stForm"] { padding: 18px; }
    [data-testid="stTabs"] [role="tab"] {
        padding: 0 10px; height: auto; min-height: 42px;
    }
}
</style>
"""


def aplicar_estilos() -> None:
    """Aplica el diseño visual mediante CSS local, sin recursos externos."""
    st.html(ESTILOS)


def mostrar_cabecera(completa: bool = True) -> None:
    """Muestra la identidad visual y, opcionalmente, la bienvenida."""
    st.html("""
        <div class="ts-brand">
            <div class="ts-wordmark">✈ Trip<span>Shield</span></div>
            <div class="ts-note">TU CUADERNO DE VIAJE</div>
        </div>
    """)

    if not completa:
        return
    st.html("""
        <div class="ts-brand">
            <div class="ts-wordmark">✈ Trip<span>Shield</span></div>
            <div class="ts-note">TU CUADERNO DE VIAJE</div>
        </div>
        <section class="ts-hero" aria-label="Bienvenida a TripShield">
            <div>
                <div class="ts-eyebrow">RUTAS PARA COMPARTIR</div>
                <h1>Tus viajes,<br><em>con tu gente cerca.</em></h1>
                <p>Organiza tus etapas, protege tus itinerarios y comparte
                tu viaje con una persona de confianza.</p>
            </div>
            <div class="ts-ticket" aria-hidden="true">
                <div class="ts-ticket-top">TRIPSHIELD · CUADERNO DE VIAJE</div>
                <div class="ts-route">
                    <span>AQUÍ</span><span class="ts-flight">· · ✈ · ·</span>
                    <span>ALLÍ</span>
                </div>
                <div class="ts-ticket-bottom">
                    TU RUTA &nbsp; <strong>Etapa a etapa</strong><br>
                    Guárdala. Compártela. Buen viaje.
                </div>
            </div>
        </section>
    """)
