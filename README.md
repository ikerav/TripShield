# TripShield

Aplicación académica para compartir itinerarios de viaje con un contacto de
confianza y registrar declaraciones de llegada mediante firmas digitales.

**Asignatura:** Criptografía y Seguridad Informática, UC3M.

## Funcionalidades

- Registro e inicio de sesión con contraseñas protegidas mediante Scrypt.
- Creación de itinerarios con entre una y cinco etapas desde la interfaz.
- Cifrado autenticado de los itinerarios mediante AES-256-GCM.
- Compartición con un único contacto registrado, con acceso de lectura
  y previa verificación de la contraseña del propietario.
- Confirmación de cada etapa por su propietario, introduciendo su contraseña.
- Firma digital Ed25519 y comprobación del certificado X.509 del firmante.
- Emisión y validación de certificados mediante OpenSSL.

Una confirmación es una declaración del usuario: la aplicación no comprueba
su ubicación física mediante GPS.

## Entorno y dependencias

La aplicación está desarrollada en Python y utiliza las siguientes dependencias:

| Dependencia | Versión |
| --- | --- |
| Streamlit | 1.65.0 |
| cryptography | 50.0.2 |
| pytest | 9.2.0 |
| OpenSSL | 3.5.9 |

Las dependencias de Python están fijadas en `requirements.txt`.

OpenSSL debe estar instalado en el sistema y disponible desde la terminal.
Esta implementación se ha probado en Linux con OpenSSL 3.5.9.

## Instalación desde cero

Estos pasos crean una instalación nueva, con sus propias claves y cuentas.
Para continuar una instalación existente, consulta el apartado de arranque.

### 1. Descargar el código y preparar Python

La versión que delega la gestión de certificados en OpenSSL se encuentra
en la rama `feature-pki-externa`.

```bash
git clone --branch feature-pki-externa https://github.com/ikerav/TripShield.git TripShield
cd TripShield

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

En VS Code, abre esta carpeta y selecciona el intérprete de `.venv` mediante
`Python: Select Interpreter` en la paleta de comandos.

### 2. Comprobar OpenSSL

```bash
openssl version
```

Se recomienda utilizar OpenSSL 3.5.9, versión con la que se ha probado
esta implementación.

### 3. Crear la autoridad de certificación

Por defecto, la CA se almacena fuera del repositorio, en:

```text
~/.tripshield/pki-externa/
```

Para utilizar otra ubicación, establece la variable de entorno
`TRIPSHIELD_CA_DIR` antes de configurar y ejecutar la aplicación:

```bash
export TRIPSHIELD_CA_DIR="$HOME/.tripshield/pki-prueba"
```

Crea la autoridad de certificación mediante OpenSSL:

```bash
CA_DIR="${TRIPSHIELD_CA_DIR:-$HOME/.tripshield/pki-externa}"

(
    umask 077
    mkdir -p "$(dirname "$CA_DIR")" &&
    mkdir "$CA_DIR" &&
    openssl req -new -x509 -newkey ed25519 \
        -keyout "$CA_DIR/ca_key.pem" \
        -out "$CA_DIR/ca_cert.pem" \
        -days 1825 \
        -subj "/O=TripShield/CN=TripShield Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign"
)
```

OpenSSL solicitará una contraseña para proteger la clave privada de la CA.
Utiliza una contraseña robusta de al menos 16 caracteres, independiente
de las contraseñas de los usuarios y de la contraseña maestra.

Se generan dos archivos:

- `ca_key.pem`: clave privada de la CA, protegida mediante cifrado.
- `ca_cert.pem`: certificado raíz público y autofirmado.

El directorio debe ser nuevo para evitar sobrescribir una CA existente.

Comprueba el certificado raíz:

```bash
openssl verify -x509_strict -check_ss_sig \
    -trusted "$CA_DIR/ca_cert.pem" \
    "$CA_DIR/ca_cert.pem"
```

El resultado esperado es `OK`.

### 4. Crear la configuración y la clave maestra

Ejecuta el siguiente bloque completo desde la carpeta del proyecto:

```bash
python - <<'PY'
import os
import json
import secrets
from pathlib import Path
from getpass import getpass

from keys import MASTER_KEY_FILE, crear_clave_maestra
from pki import emitir_certificado_usuario
from signatures import generar_claves_firma

carpeta = Path(".streamlit")
configuracion = carpeta / "secrets.toml"

if configuracion.exists() or MASTER_KEY_FILE.exists():
    raise SystemExit("Ya existe una instalación local.")

carpeta.mkdir(mode=0o700, exist_ok=True)

password_ca = getpass("Contraseña de la CA: ")

_, publica = generar_claves_firma()
emitir_certificado_usuario("usuario_prueba", publica, password_ca)

password_maestra = secrets.token_urlsafe(32)

descriptor = os.open(
    configuracion, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
)

with os.fdopen(descriptor, "w", encoding="utf-8") as archivo:
    archivo.write(f'MASTER_PASSWORD = {json.dumps(password_maestra)}\n')
    archivo.write(f'CA_PASSWORD = {json.dumps(password_ca)}\n')

crear_clave_maestra(password_maestra)

print("Configuración local y clave maestra creadas correctamente.")
PY
```

Este proceso comprueba la contraseña de la CA, genera una contraseña maestra
aleatoria e independiente y crea la clave maestra protegida.

Las contraseñas del servidor se almacenan en `.streamlit/secrets.toml`,
un archivo local excluido del repositorio.

Si la configuración falla después de crear alguno de los archivos,
revisa la instalación antes de volver a ejecutar el bloque.

### 5. Ejecutar las pruebas y abrir la aplicación

```bash
python -m pytest -q
python -m streamlit run app.py
```

Abre la dirección local que indique Streamlit, normalmente:

```text
http://localhost:8501
```

Para detener la aplicación, pulsa `Ctrl + C` en la terminal.

La instalación nueva no contiene cuentas ni viajes. Crea dos cuentas
ficticias desde la pestaña **Registrarse** para probar el propietario
y su contacto.

## Arranque de una instalación existente

Desde la carpeta del proyecto:

```bash
source .venv/bin/activate
python -m streamlit run app.py
```

Si configuraste `TRIPSHIELD_CA_DIR`, establece previamente su valor original.

No es necesario volver a generar la CA ni la clave maestra.
Conserva los archivos de configuración y los datos de la instalación.

## Uso y comprobación manual

1. Registra una cuenta e inicia sesión. Comprueba también una contraseña
   incorrecta.
2. Crea un viaje con una o varias etapas.
3. Comparte el viaje con una segunda cuenta registrada, introduciendo
   la contraseña del propietario.
4. Comprueba que una contraseña incorrecta impide compartir el viaje.
5. Como propietario, confirma una etapa introduciendo tu contraseña.
6. Como contacto, consulta el viaje y comprueba la validez de la firma
   digital y la identidad certificada del firmante.
7. Comprueba que el contacto no puede confirmar llegadas y que una tercera
   cuenta no puede consultar el viaje.

## Estructura del código

| Archivo | Responsabilidad |
| --- | --- |
| `app.py` | Interfaz y gestión de la sesión de Streamlit. |
| `estilos.py` | Estilos locales y cabecera de cuaderno de viaje. |
| `.streamlit/config.toml` | Tema visual compartido de la aplicación. |
| `auth.py` | Registro, autenticación y claves certificadas de las cuentas. |
| `storage.py` | Lectura y actualización de usuarios en JSON. |
| `keys.py` | Creación y recuperación de la clave maestra protegida. |
| `encryption.py` | Cifrado y descifrado autenticados de itinerarios. |
| `signatures.py` | Protección de claves privadas Ed25519 y firmas digitales. |
| `trips.py` | Viajes, permisos, compartición y confirmaciones de llegada. |
| `pki.py` | Emisión y validación de certificados mediante OpenSSL. |
| `tests/` | Pruebas automatizadas de funcionamiento y seguridad. |
| `tests/util_ca.py` | Creación de autoridades certificadoras temporales para las pruebas. |

## Decisiones criptográficas

### Autenticación

Las contraseñas se protegen mediante Scrypt con los parámetros:

- `n = 2**15`
- `r = 8`
- `p = 1`
- Sal aleatoria de 16 bytes.
- Resultado de 32 bytes.

Se almacenan la sal y el resultado de Scrypt, nunca la contraseña
del usuario.

### Cifrado e integridad

Los itinerarios se protegen mediante AES-256-GCM, utilizando un nonce
aleatorio de 12 bytes y una etiqueta de autenticación de 16 bytes.

El AAD vincula el viaje con su identificador, propietario y contacto
cuando existe. Cualquier error de autenticación provoca el rechazo
del contenido.

Cada operación de cifrado genera un nuevo nonce aleatorio.

### Protección de claves

La clave maestra y las claves privadas de los usuarios se protegen
mediante AES-256-GCM.

Las claves de protección se derivan mediante Scrypt con:

- `n = 2**17`
- `r = 8`
- `p = 1`
- Sales aleatorias e independientes de 16 bytes.
- Resultado de 32 bytes.

La clave privada de la CA se almacena en formato PKCS8 cifrado,
gestionado por OpenSSL y protegido con una contraseña independiente.

### Firmas digitales

Las confirmaciones de llegada se firman mediante Ed25519 sobre un JSON
de representación estable y un prefijo de contexto.

El mensaje firmado incluye el identificador del viaje, el propietario,
el índice y los datos de la etapa, la versión y la fecha de confirmación
en UTC.

Esto permite detectar alteraciones del mensaje y evitar la reutilización
de una confirmación en otro viaje o etapa.

### Certificados digitales y PKI

TripShield utiliza una autoridad de certificación privada con una raíz
Ed25519 autofirmada y una vigencia de 1.825 días.

La CA emite certificados X.509 para vincular las claves públicas
Ed25519 con las cuentas de los usuarios.

Los certificados de usuario:

- Tienen una vigencia máxima de 365 días.
- No pueden superar la vigencia de la CA.
- Identifican al usuario mediante el campo Common Name (CN).
- Están destinados exclusivamente a la firma digital.
- No tienen permisos para actuar como autoridades de certificación.

La creación de la CA, la emisión de certificados y la validación
criptográfica de la cadena de confianza se delegan en OpenSSL.

Python realiza las comprobaciones específicas de TripShield, como la
correspondencia entre el nombre certificado y la cuenta, el algoritmo
de clave pública, el perfil de firma y la extracción de la clave
pública certificada.

La integración se realiza mediante `subprocess.run()`, sin utilizar
un intérprete de comandos. La contraseña de la CA se transmite a
OpenSSL mediante la entrada estándar, no como argumento del proceso.

La raíz de confianza procede de la configuración del servidor,
nunca del registro de usuarios.

La validación de certificados no requiere acceder a la clave
privada de la CA.

### Reautenticación

Las operaciones sensibles, como compartir un viaje o firmar una
llegada, requieren introducir nuevamente la contraseña del propietario.

La comprobación se realiza en la lógica de la aplicación, no únicamente
en la interfaz.

### Migración de cuentas

Las cuentas antiguas sin certificado se actualizan al autenticarse.
Cuando ya tienen un par de firma, se comprueba su correspondencia y
se conserva ese par, sin invalidar las firmas anteriores.

Un certificado presente pero inválido se rechaza y no se sustituye
automáticamente por uno nuevo.

## Pruebas automatizadas

Ejecuta desde la raíz del proyecto:

```bash
python -m pytest -q
```

La versión actual contiene **129 casos de prueba**.

Las pruebas que necesitan almacenamiento o una CA utilizan ubicaciones
temporales, sin modificar los datos locales de la aplicación.

Entre los casos comprobados se incluyen:

- Contraseñas incorrectas.
- Alteraciones del cifrado y de su etiqueta de autenticación.
- Uso de claves de cifrado incorrectas.
- Manipulación y sobrescritura de la clave maestra.
- Alteración de claves privadas protegidas.
- Firmas digitales inválidas.
- Reutilización de confirmaciones en otros viajes o etapas.
- Acceso de usuarios no autorizados.
- Manipulación de los archivos de almacenamiento.
- Certificados caducados o todavía no vigentes.
- Certificados manipulados, de otra cuenta o emitidos por otra CA.
- Manipulación del certificado raíz.
- Contraseña incorrecta de la CA.
- Incoherencia entre la clave privada y el certificado de la CA.
- Identificadores de usuario inválidos.
- Compartición de viajes con una contraseña incorrecta.

## Archivos locales y copias de seguridad

| Archivo o directorio | Contenido |
| --- | --- |
| `data/users.json` | Cuentas, credenciales protegidas y claves de firma. |
| `data/trips.json` | Itinerarios cifrados. |
| `data/master_key.json` | Clave maestra protegida. |
| `.streamlit/secrets.toml` | Contraseñas locales del servidor. |
| `~/.tripshield/pki-externa/ca_key.pem` | Clave privada cifrada de la CA. |
| `~/.tripshield/pki-externa/ca_cert.pem` | Certificado raíz público. |

Estos archivos no se incluyen en Git.

Para conservar una instalación, deben respaldarse conjuntamente
los datos, la configuración local y los archivos de su CA.

No se deben publicar contraseñas, claves privadas, copias de seguridad
ni datos personales reales.

## Alcance y limitaciones

TripShield es un prototipo académico con un servidor de confianza.
El servidor puede descifrar los itinerarios y procesa las contraseñas
durante el acceso o la firma. No ofrece cifrado de extremo a extremo.

La PKI vincula las claves públicas con las cuentas de TripShield,
pero no verifica la identidad civil de los usuarios. La autoridad
de certificación es privada y no depende de entidades externas.

Los identificadores de usuario deben contener entre 3 y 30 caracteres
ASCII imprimibles. Esta restricción evita problemas de codificación
durante la emisión de certificados mediante OpenSSL.

Los certificados se validan respecto al momento actual. No se
implementan mecanismos de renovación automática, revocación mediante
CRL/OCSP ni sellado de tiempo de confianza.

Un certificado caducado provoca el rechazo de la verificación,
aunque la declaración indique una fecha anterior.

Se rechazan las confirmaciones duplicadas y su reutilización en otro
viaje o etapa, pero no existe un registro inmutable que detecte
la restauración completa de archivos antiguos.

Los bloqueos de almacenamiento coordinan hilos de un único proceso.
No se ofrece coordinación entre múltiples procesos, recuperación de
contraseñas, verificación mediante GPS ni notificaciones externas.

La ejecución documentada es local.