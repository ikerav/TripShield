# TripShield

Aplicación académica para compartir itinerarios de viaje con un contacto de
confianza y registrar declaraciones de llegada mediante firmas digitales.

**Asignatura:** Criptografía y Seguridad Informática, UC3M.

## Funcionalidades

- Registro e inicio de sesión con contraseñas protegidas mediante Scrypt.
- Creación de itinerarios con entre una y cinco etapas.
- Cifrado autenticado de itinerarios mediante AES-256-GCM.
- Compartición con un único contacto registrado, con acceso de lectura
  y previa verificación de la contraseña del propietario.
- Confirmación de cada etapa mediante una firma digital Ed25519.
- Certificados X.509 para vincular las claves públicas con las cuentas.
- Emisión y validación de certificados mediante cryptography.

Una confirmación es una declaración del usuario: la aplicación no comprueba
su ubicación física mediante GPS.

## Entorno y dependencias

La aplicación está desarrollada en Python y utiliza las siguientes bibliotecas:

| Dependencia | Versión |
| --- | --- |
| Streamlit | 1.65.0 |
| cryptography | 50.0.2 |
| pytest | 9.2.0 |

Las versiones están fijadas en `requirements.txt`.

Todas las operaciones criptográficas se realizan mediante la biblioteca
cryptography. No es necesario instalar pyOpenSSL, el ejecutable de OpenSSL
ni configurar un servicio externo de certificación.

## Instalación desde cero

### 1. Descargar el proyecto

```bash
git clone --branch feature-pki-cryptography https://github.com/ikerav/TripShield.git TripShield
cd TripShield
```

### 2. Crear el entorno virtual e instalar las dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

En VS Code, selecciona el intérprete de `.venv` mediante
`Python: Select Interpreter` en la paleta de comandos.

### 3. Configurar la instalación

```bash
python setup_local.py
```

Este comando genera automáticamente:

- Una contraseña maestra aleatoria.
- Una clave maestra AES-256 protegida mediante cifrado.
- Una autoridad de certificación privada Ed25519.
- Una contraseña independiente para proteger la privada de la CA.
- El archivo local `.streamlit/secrets.toml`.

Los archivos de la autoridad de certificación se almacenan en `data/pki/`.

El script de configuración se ejecuta una única vez y no sobrescribe
una instalación existente. Si la configuración se interrumpe, deben
revisarse los archivos generados antes de repetir el proceso.

### 4. Ejecutar las pruebas

```bash
python -m pytest -q
```

### 5. Arrancar la aplicación

```bash
python -m streamlit run app.py
```

Abre la dirección local indicada por Streamlit, normalmente
`http://localhost:8501`.

La instalación nueva no contiene cuentas ni viajes. Es necesario registrar
los usuarios desde la propia interfaz.

## Arranque de una instalación existente

```bash
source .venv/bin/activate
python -m streamlit run app.py
```

No es necesario volver a ejecutar `setup_local.py`.

## Uso y comprobación manual

1. Registra dos cuentas e inicia sesión con una de ellas.
2. Crea un viaje con una o varias etapas.
3. Comparte el viaje con la segunda cuenta, introduciendo la contraseña
   del propietario.
4. Comprueba que una contraseña incorrecta impide compartir el viaje.
5. Confirma una etapa desde la cuenta del propietario, introduciendo
   nuevamente su contraseña.
6. Accede desde la cuenta del contacto y comprueba la validez de la firma
   digital y la identidad certificada del firmante.
7. Comprueba que el contacto no puede confirmar llegadas y que una tercera
   cuenta no puede consultar el viaje.

## Estructura del código

| Archivo | Responsabilidad |
| --- | --- |
| `app.py` | Interfaz y gestión de sesiones mediante Streamlit. |
| `estilos.py` | Estilos visuales de la aplicación. |
| `auth.py` | Registro, autenticación y claves certificadas. |
| `storage.py` | Almacenamiento y recuperación de usuarios. |
| `keys.py` | Creación y recuperación de la clave maestra protegida. |
| `encryption.py` | Cifrado y descifrado autenticados. |
| `signatures.py` | Protección de claves privadas y firmas Ed25519. |
| `trips.py` | Gestión de viajes, permisos y confirmaciones. |
| `pki.py` | Emisión y validación de certificados X.509 mediante cryptography. |
| `setup_local.py` | Configuración inicial de claves, secretos y CA. |
| `tests/` | Pruebas automatizadas de funcionamiento y seguridad. |

## Decisiones criptográficas

### Autenticación

Las contraseñas de los usuarios se protegen mediante Scrypt:

- `n = 2**15`
- `r = 8`
- `p = 1`
- Sal aleatoria de 16 bytes.
- Resultado de 32 bytes.

Se almacenan la sal y el resultado de Scrypt, nunca la contraseña
del usuario.

Durante el registro también se genera el par de claves Ed25519 del usuario
y se emite su certificado digital.

El inicio de sesión comprueba las credenciales y valida el certificado
existente, sin generar nuevas claves ni certificados.

### Cifrado e integridad

Los itinerarios se protegen mediante AES-256-GCM, utilizando un nonce
aleatorio de 12 bytes y una etiqueta de autenticación de 16 bytes.

El AAD vincula el itinerario con su identificador, propietario y contacto
cuando existe.

Cualquier error de autenticación provoca el rechazo del contenido.

Cada operación de cifrado genera un nuevo nonce aleatorio. No existe
un registro de nonces utilizados, por lo que su unicidad es probabilística.

### Protección de claves

La clave maestra y las claves privadas Ed25519 de los usuarios se protegen
mediante AES-256-GCM.

Las claves de protección se derivan mediante Scrypt:

- `n = 2**17`
- `r = 8`
- `p = 1`
- Sales independientes de 16 bytes.
- Resultado de 32 bytes.

La clave privada de la CA se almacena en formato PKCS8 cifrado mediante
`BestAvailableEncryption` de cryptography y una contraseña independiente.

Las claves se generan mediante las bibliotecas criptográficas utilizadas.
Las sales y los nonces se obtienen mediante `os.urandom`, y las contraseñas
de configuración se generan mediante `secrets`.

### Firmas digitales

Las confirmaciones de llegada se firman mediante Ed25519 sobre un JSON
de representación estable y un prefijo de contexto.

El mensaje firmado incluye el identificador del viaje, propietario,
índice y datos de la etapa, versión y fecha de confirmación en UTC.

Esto permite detectar alteraciones del mensaje y evita que una firma
válida pueda reutilizarse en otro viaje o etapa.

Antes de firmar, se comprueba que la clave privada del usuario corresponde
a la clave pública de su certificado.

### Certificados digitales

TripShield utiliza una PKI privada con una única autoridad raíz para
vincular las claves públicas Ed25519 con las cuentas de los usuarios.

El servidor actúa como autoridad de certificación (CA). La CA se configura
durante la instalación y emite certificados X.509 exclusivamente durante
el registro de nuevos usuarios.

La autoridad raíz tiene una vigencia de 1.825 días y no admite
autoridades intermedias.

Los certificados de usuario:

- Tienen una vigencia máxima de 365 días.
- No superan la vigencia de la CA.
- Identifican a la cuenta mediante el campo Common Name (CN).
- Permiten exclusivamente la firma digital.

La emisión de certificados utiliza `CertificateBuilder` de cryptography.

Para verificar la firma de un certificado y su correspondencia con el
emisor se utiliza el método `verify_directly_issued_by()` de cryptography.

Dado que este método no realiza una validación X.509 completa, la
aplicación comprueba adicionalmente:

- La vigencia del certificado raíz y del certificado del usuario.
- La versión X.509.
- Los algoritmos de clave pública y firma.
- La identidad certificada del usuario.
- Las restricciones de autoridad certificadora (`BasicConstraints`).
- Los usos permitidos de la clave (`KeyUsage`).
- Las extensiones admitidas por el perfil de TripShield.
- La correspondencia entre los identificadores de autoridad y sujeto.
- Que la vigencia del certificado del usuario esté comprendida dentro
  de la vigencia de la CA.

La clave pública del usuario se obtiene directamente de su certificado
X.509, evitando almacenarla por duplicado.

La validación no requiere acceder a la clave privada de la CA.

No se implementan algoritmos criptográficos desde cero ni un verificador
X.509 de propósito general. La validación está limitada al perfil de
certificados utilizado por TripShield.

### Reautenticación

Compartir un viaje y firmar una confirmación requieren introducir
nuevamente la contraseña del propietario.

Esta comprobación se realiza en la lógica de la aplicación, no únicamente
en la interfaz.

## Pruebas automatizadas

```bash
python -m pytest -q
```

La implementación contiene **114 casos de prueba**.

Las pruebas utilizan archivos y autoridades certificadoras temporales,
sin modificar los datos de la instalación real.

Se comprueban, entre otros casos:

- Contraseñas incorrectas.
- Alteración del cifrado y de las etiquetas de autenticación.
- Uso de claves incorrectas.
- Manipulación y sobrescritura de la clave maestra.
- Alteración de claves privadas protegidas.
- Firmas digitales inválidas.
- Reutilización de confirmaciones en otros viajes o etapas.
- Acceso de usuarios no autorizados.
- Compartición de viajes con una contraseña incorrecta.
- Manipulación de los archivos de almacenamiento.
- Certificados caducados, prematuros o manipulados.
- Certificados de otra cuenta o emitidos por otra CA.
- Manipulación del certificado raíz.
- Contraseña incorrecta de la CA.
- Incoherencia entre la privada y el certificado raíz.
- Incoherencia entre la privada del usuario y su certificado.
- Rechazo de cuentas sin certificado o con datos incompletos.
- Identificadores de usuario con caracteres especiales y Unicode.

## Archivos locales y copias de seguridad

| Archivo o directorio | Contenido |
| --- | --- |
| `data/users.json` | Cuentas, credenciales protegidas, privadas cifradas y certificados. |
| `data/trips.json` | Itinerarios cifrados. |
| `data/master_key.json` | Clave maestra cifrada. |
| `data/pki/ca_key.pem` | Clave privada cifrada de la CA. |
| `data/pki/ca_cert.pem` | Certificado raíz público. |
| `.streamlit/secrets.toml` | Contraseñas locales del servidor. |

Estos archivos no se incluyen en el repositorio.

Para conservar una instalación, deben respaldarse conjuntamente el
directorio `data/` y el archivo `.streamlit/secrets.toml`.

No deben publicarse contraseñas, claves privadas ni datos personales reales.

## Alcance y limitaciones

TripShield es un prototipo académico con un servidor de confianza.
El servidor puede descifrar los itinerarios y procesa las contraseñas
durante la autenticación y la firma. No ofrece cifrado de extremo a extremo.

Los certificados vinculan claves públicas con cuentas de TripShield,
pero no acreditan la identidad civil de los usuarios.

La autoridad de certificación es privada y la confianza en su certificado
raíz depende de la protección de la instalación del servidor.

La validación se limita a certificados emitidos directamente por la
autoridad raíz de TripShield. No se admiten autoridades intermedias ni
cadenas de certificación arbitrarias.

La validación de certificados se realiza respecto al momento actual.
No se implementan renovación automática, revocación mediante CRL/OCSP
ni sellado de tiempo de confianza.

Un certificado caducado provoca el rechazo de la verificación, aunque
la declaración indique una fecha anterior.

Se rechazan las confirmaciones duplicadas y su reutilización en otros
viajes o etapas. No existe un registro inmutable que permita detectar
la restauración completa de archivos antiguos.

Los bloqueos de almacenamiento coordinan hilos de un único proceso.
No se ofrece coordinación entre múltiples procesos, recuperación de
contraseñas, verificación mediante GPS ni notificaciones externas.

La ejecución documentada es local.