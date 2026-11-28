# TripShield

Proyecto de la asignatura Criptografía y Seguridad Informática (UC3M).

TripShield es una aplicación desarrollada en Python y Streamlit que permite crear itinerarios de viaje, compartirlos con un contacto de confianza y confirmar las llegadas a las distintas etapas.

## Funcionalidades

- Registro e inicio de sesión con contraseñas protegidas mediante Scrypt.
- Creación y compartición de itinerarios cifrados con AES-256-GCM.
- Confirmación de llegadas mediante firmas digitales Ed25519.
- Certificados X.509 para vincular las claves públicas con los usuarios.

## Instalación

Se necesita tener Python instalado. El proyecto se ha probado con Python 3.10.11 y 3.14.9.

### 1. Descargar el proyecto

```bash
git clone https://github.com/ikerav/TripShield.git
cd TripShield
```

Si se dispone del ZIP del proyecto, basta con descomprimirlo y abrir una terminal en la carpeta correspondiente.

### 2. Crear el entorno virtual e instalar las dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Generar la configuración inicial

```bash
python setup_local.py
```

Este paso genera la clave maestra, la autoridad de certificación y las contraseñas de configuración. Solo debe realizarse la primera vez.

### 4. Ejecutar la aplicación

```bash
python -m streamlit run app.py
```

La aplicación estará disponible en http://localhost:8501.

## Pruebas

Para ejecutar las 114 pruebas automatizadas:

```bash
python -m pytest -q
```

## Datos locales

Los archivos generados en `data/` y `.streamlit/secrets.toml` deben conservarse para poder seguir utilizando las cuentas y los viajes creados. Estos archivos no se incluyen en el repositorio.

## Autores

- David Larrea Suárez
- Iker Alcaide Velasco