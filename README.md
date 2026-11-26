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
- Firma Ed25519 y comprobación del certificado X.509 de la cuenta firmante.

Una confirmación es una declaración del usuario: la aplicación no comprueba
su ubicación física mediante GPS.

## Entorno y dependencias

Entorno utilizado: macOS, Python 3.10.11 y las siguientes versiones:

| Dependencia | Versión |
| --- | --- |
| Streamlit | 1.65.0 |
| cryptography | 50.0.2 |
| pytest | 9.2.0 |
| tomli, solo para Python anterior a 3.11 | 2.5.0 |

Las versiones de las dependencias directas están fijadas en `requirements.txt`.
Los comandos siguientes utilizan una terminal de macOS o Linux.

## Instalación desde cero

Estos pasos crean una instalación nueva, con sus propias claves y cuentas.
Para continuar una instalación existente, consulta el apartado de arranque.

### 1. Descargar el código y preparar Python

La versión con PKI se encuentra actualmente en la rama `feature-pki`.

```bash
git clone --branch feature-pki https://github.com/ikerav/TripShield.git TripShield
cd TripShield
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

En VS Code, abre esta carpeta y selecciona el intérprete de `.venv` mediante
`Python: Select Interpreter` en la paleta de comandos.

### 2. Elegir la ubicación de la CA

Por defecto, la autoridad de certificación se guarda fuera del repositorio,
en `~/.tripshield/pki`. Esa ubicación contiene la raíz de confianza de esta
instalación y debe estar bajo el control del administrador.

Si ya tienes otra instalación en el mismo ordenador, elige una carpeta nueva
antes de continuar. Por ejemplo:

```bash
export TRIPSHIELD_CA_DIR="$HOME/.tripshield/pki-prueba"
```

Utiliza una ruta absoluta fuera del repositorio. Esta variable es configuración
del servidor, no un dato proporcionado por los usuarios de la aplicación.
Si la utilizas, debes establecer el mismo valor al configurar la CA y al
arrancar la aplicación, también cuando abras una terminal nueva.

### 3. Crear la configuración y la clave maestra

Ejecuta el bloque completo desde la carpeta del proyecto. Genera una contraseña
aleatoria y la guarda en la configuración local sin mostrarla en pantalla.
El bloque se detiene si ya existe configuración o una clave maestra.

```bash
python - <<'PY'
import os
import secrets
from pathlib import Path

from keys import MASTER_KEY_FILE, crear_clave_maestra

carpeta = Path(".streamlit")
configuracion = carpeta / "secrets.toml"

if configuracion.exists() or MASTER_KEY_FILE.exists():
    raise SystemExit("Ya hay una instalación local. Conserva sus archivos.")

carpeta.mkdir(mode=0o700, exist_ok=True)
password = secrets.token_urlsafe(32)

descriptor = os.open(
    configuracion, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
)
with os.fdopen(descriptor, "w", encoding="utf-8") as archivo:
    archivo.write(f'MASTER_PASSWORD = "{password}"\n')

crear_clave_maestra(password)
print("Configuración local y clave maestra creadas correctamente.")
PY
```

### 4. Inicializar la autoridad de certificación

```bash
python init_pki.py
```

El programa genera una contraseña independiente para la CA, la añade a
`.streamlit/secrets.toml` y guarda la privada cifrada y el certificado raíz en
la ubicación configurada. Repetir el comando verifica una CA ya configurada
sin sustituir sus claves.

Si encuentra archivos incompletos, una CA sin su contraseña o datos inválidos,
detiene la configuración. Conserva esos archivos antes de revisar el problema;
regenerar las claves impediría utilizar los datos que dependan de las anteriores.

### 5. Ejecutar las pruebas y abrir la aplicación

```bash
python -m pytest -q
python -m streamlit run app.py
```

Abre la dirección local que indique Streamlit, normalmente
`http://localhost:8501`. Para detener la aplicación, pulsa `Ctrl + C` en la terminal.

La instalación nueva no contiene cuentas ni viajes. Crea dos cuentas ficticias
desde la pestaña **Registrarse** para probar el propietario y su contacto.

## Arranque de una instalación existente

Desde la carpeta del proyecto, activa el entorno y ejecuta la aplicación:

```bash
source .venv/bin/activate
python -m streamlit run app.py
```

Si configuraste `TRIPSHIELD_CA_DIR`, establece previamente su valor original.
Conserva la configuración, los archivos de `data/` y la CA de esa instalación.

## Uso y comprobación manual

1. Registra una cuenta e inicia sesión; comprueba también una contraseña errónea.
2. Crea un viaje y comprueba que aparece el aviso de guardado.
3. Comparte el viaje con una segunda cuenta registrada, introduciendo
   la contraseña del propietario. Comprueba que una contraseña incorrecta
   impide la compartición.
4. Como propietario, confirma una etapa introduciendo tu contraseña.
5. Como contacto, consulta el viaje y comprueba la validez de la firma
   digital y la identidad certificada del firmante.
6. Comprueba que el contacto no dispone del formulario para confirmar llegadas
   y que una tercera cuenta no puede consultar el viaje.

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
| `signatures.py` | Protección de privadas Ed25519 y firmas de declaraciones. |
| `trips.py` | Viajes, permisos, compartición y confirmaciones de llegada. |
| `pki.py` | Creación, emisión y validación de la CA y los certificados. |
| `init_pki.py` | Configuración inicial de la CA local. |
| `tests/` | Pruebas automatizadas de funcionamiento y seguridad. |

## Decisiones criptográficas

- **Contraseñas:** Scrypt con `n=2**15`, `r=8`, `p=1`, salida de 32 bytes y sal
  aleatoria de 16 bytes. Se almacenan la sal y el resultado, nunca la contraseña.
- **Itinerarios:** AES-256-GCM, nonce aleatorio de 12 bytes y etiqueta de 16 bytes.
  El AAD vincula el viaje con su identificador, propietario y contacto cuando
  existe. Un error de autenticación provoca el rechazo del contenido.
- **Protección de claves:** la clave maestra y las privadas de usuario se cifran
  con AES-256-GCM. Sus claves de protección se derivan mediante Scrypt con
  `n=2**17`, `r=8`, `p=1`, salida de 32 bytes y sales independientes de 16 bytes.
  La privada de la CA utiliza PKCS8 cifrado con `BestAvailableEncryption` y una
  contraseña independiente.
- **Firmas:** Ed25519 sobre un JSON de representación estable y un prefijo de
  contexto. La declaración incluye el viaje, propietario, índice y datos de
  etapa, versión y fecha de confirmación en UTC.
- **PKI:** raíz Ed25519 autofirmada, con vigencia de 1.825 días, sin intermediarias.
  Los certificados finales duran como máximo 365 días y nunca superan la
  vigencia de la raíz. La verificación comprueba la firma del emisor, vigencia,
  identidad de cuenta, tipo de clave, restricciones y usos permitidos. La raíz
  se obtiene de la configuración del servidor, nunca del registro de usuarios.
- **Aleatoriedad:** claves generadas por la biblioteca criptográfica; sales y
  nonces mediante `os.urandom`; contraseñas locales mediante `secrets`. Cada
  cifrado genera un nonce nuevo, con una probabilidad de colisión muy baja,
  sin una garantía absoluta de unicidad ni un registro de nonces utilizados.
- **Reautenticación:** las operaciones sensibles, como compartir un viaje
  o firmar una llegada, requieren introducir nuevamente la contraseña
  del propietario. La comprobación se realiza en la lógica de la aplicación,
  no únicamente en la interfaz.

Las cuentas antiguas sin certificado se actualizan al autenticarse. Cuando ya
tienen un par de firma, se comprueba su correspondencia y se conserva ese par,
sin invalidar las firmas anteriores. Un certificado presente pero inválido
se rechaza; no se sustituye automáticamente por uno nuevo.

## Pruebas automatizadas

Ejecuta `python -m pytest -q` desde la raíz del proyecto.
La versión actual contiene **140 casos**, organizados en la carpeta `tests/`.

Las pruebas que necesitan almacenamiento o una CA utilizan ubicaciones
temporales, sin modificar los datos locales de la aplicación.

Se comprueban, entre otros casos, contraseñas incorrectas, alteraciones del
cifrado y de su etiqueta, claves equivocadas, manipulación y sobrescritura
de la clave maestra, manipulación del contacto, privadas protegidas
alteradas, firmas inválidas, reutilización de una llegada en otro viaje
o etapa, permisos, duplicados, archivos JSON dañados y rechazo de
certificados caducados, prematuros, de otra cuenta o de otra CA.

También se comprueba que compartir un viaje con una contraseña incorrecta
no modifica el itinerario ni concede acceso al contacto.

## Archivos locales y copias de seguridad

`data/` contiene usuarios, itinerarios cifrados y la clave maestra cifrada.
`.streamlit/secrets.toml` contiene las contraseñas locales del servidor.
El tema visual `.streamlit/config.toml` sí se incluye en Git y no contiene secretos.
La carpeta de la CA contiene `ca_key.pem`, cifrado, y `ca_cert.pem`.

Estos archivos privados no se incluyen en Git. Para conservar una instalación,
respalda conjuntamente `data/`, la configuración local y la carpeta de su CA
en una ubicación privada fuera del repositorio. No publiques contraseñas,
privadas, copias de seguridad ni datos personales reales.

## Alcance y limitaciones

Es un prototipo con servidor de confianza: el servidor puede descifrar los
itinerarios y procesa las contraseñas durante el acceso o la firma. La PKI
vincula claves con cuentas de TripShield, sin verificar una identidad civil.

Los certificados se validan respecto al momento actual. No hay renovación
automática, revocación mediante CRL/OCSP ni sellado de tiempo de confianza.
Un certificado caducado provoca rechazo aunque la declaración indique una
fecha anterior. La fecha firmada procede del reloj del servidor.

Se rechazan confirmaciones duplicadas y copias a otro viaje o etapa; no existe
un registro inmutable que detecte la restauración completa de archivos antiguos.
Los bloqueos de almacenamiento coordinan hilos de un único proceso. No se
ofrece coordinación entre múltiples procesos, recuperación de contraseñas,
GPS ni notificaciones externas. La ejecución documentada es local.
