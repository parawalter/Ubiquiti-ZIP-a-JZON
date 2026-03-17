# UniFi UNF/ZIP to JSON Extractor 🚀

**Autor:** Ing. Walter Rodríguez  
**Versión:** v1.0.0  
**Última actualización:** 17/03/2026

---

## 📝 ¿Para qué sirve?

Esta herramienta está diseñada para administradores de red que trabajan con ecosistemas **Ubiquiti UniFi**. Su función principal es extraer y convertir los archivos de respaldo de UniFi (`.unf` o `.zip`) a un formato **JSON** estructurado y legible.

Normalmente, los backups de UniFi están en un formato binario encriptado y comprimido (AES + BSON/MongoDB dump) que no es fácil de inspeccionar sin restaurar en un controlador. Esta herramienta elimina esa barrera, permitiendo visualizar la configuración completa en segundos.

---

## ⚙️ Funcionamiento técnico

El proceso de extracción sigue exactamente el algoritmo oficial de Ubiquiti:

1. **Detección del tipo de archivo**: Verifica si el archivo es un `.zip` directo (sin encriptación) o un `.unf` encriptado.
2. **Desencriptación AES-128-CBC** (solo para `.unf`):
   - Clave: `bcyangkmluohmars`
   - IV: `ubntenterpriseap`
   - Modo: `NoPadding`
   - Fuente: [zhangyoufu/unifi-backup-decrypt](https://github.com/zhangyoufu/unifi-backup-decrypt)
3. **Reparación del ZIP**: Tras la desencriptación `NoPadding`, el Central Directory del ZIP puede estar corrupto. Se implementa una extracción forzada escaneando los **Local File Headers** (`PK\x03\x04`) directamente, usando `zlib.decompressobj + unused_data` para detectar el fin exacto de cada stream Deflate. Equivale al `zip -FF` del script bash oficial.
4. **Localización de `db.gz`**: Busca la base de datos MongoDB dentro del ZIP extraído.
5. **Descompresión** de `db.gz` a BSON.
6. **Conversión BSON → JSON**: Genera un archivo `.json` estructurado con indentación en la misma carpeta del backup original.

---

## ✨ Características

- ✅ Soporte nativo para archivos `.unf` **y** `.zip` de UniFi Network
- ✅ Desencriptación AES-128-CBC con la clave oficial de Ubiquiti
- ✅ Extracción forzada de ZIP malformado (sin dependencias externas)
- ✅ Interfaz moderna oscura (SaaS premium, customtkinter)
- ✅ Barra de progreso y log en tiempo real
- ✅ 100% local — ningún dato sale de tu computadora
- ✅ Sin instalación adicional para el usuario final (ejecutable `.exe`)

---

## 🚀 Uso rápido (Usuario final)

1. Descarga `UniFi_UNF_Extractor.exe` desde la carpeta `dist/`
2. Haz doble clic para abrir la aplicación
3. Haz clic en **"Seleccionar Archivo .unf / .zip"**
4. Selecciona tu backup de UniFi (`.unf` o `.zip`)
5. Haz clic en **"Convertir a JSON"**
6. El archivo `config.json` se generará en la **misma carpeta** que tu backup

---

## 🤖 El Poder del JSON con Inteligencia Artificial

Una de las mayores ventajas es la interoperabilidad del JSON con modelos de IA como **ChatGPT, Claude o Gemini**:

1. **Auditoría de Seguridad**: *"Analiza este JSON y dime si hay puertos abiertos vulnerables o configuraciones de firewall inseguras"*
2. **Documentación Automática**: *"Genera una tabla en Markdown con todos los SSIDs, VLANs y sus respectivas subredes"*
3. **Troubleshooting**: *"Compara estos dos JSONs de diferentes fechas y dime qué cambió en las VLANs"*
4. **Generación de Scripts**: *"Crea un script Python para validar que todos los APs tengan Band Steering activado"*
5. **Optimización**: La IA puede sugerir canales WiFi menos saturados basándose en la configuración detectada

---

## 🛠️ Instalación para Desarrolladores

### Requisitos previos
- Python 3.10+
- pip

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/parawalter/Ubiquiti-ZIP-a-JZON.git
cd Ubiquiti-ZIP-a-JZON

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar en modo desarrollo
python main.py

# 4. Compilar el ejecutable (opcional)
python build.py
```

### Dependencias (`requirements.txt`)

| Paquete | Propósito |
|---|---|
| `customtkinter` | Interfaz gráfica moderna |
| `pymongo` | Decodificación de BSON (incluye `bson.decode_all`) |
| `tkinterdnd2-universal` | Soporte drag & drop |
| `cryptography` | Desencriptación AES-128-CBC |
| `pyinstaller` | Compilación del ejecutable `.exe` |

---

## ⚠️ Solución de problemas comunes

### Error: `ImportError: cannot import name 'decode_all' from 'bson'`

Tienes el paquete `bson` standalone instalado, que entra en conflicto con `pymongo`. Solución:

```powershell
pip uninstall bson pymongo -y
pip install pymongo
```

### Error: `No se encontró la base de datos (db.gz o db)`

Posibles causas:
- El archivo `.zip` no es un backup de **UniFi Network** (podría ser un backup de UniFi Protect u otro producto)
- El backup proviene de una versión muy antigua o muy nueva de UniFi Controller

---

## 📂 Estructura del Proyecto

```
Ubiquiti-ZIP-a-JSON/
│
├── main.py              # Interfaz gráfica (customtkinter)
├── extractor.py         # Lógica de desencriptación y extracción
├── build.py             # Script para compilar el .exe con PyInstaller
├── requirements.txt     # Dependencias de Python
├── README.md            # Este archivo
│
└── dist/
    └── UniFi_UNF_Extractor.exe   # Ejecutable listo para usar
```

---

## 🔐 Seguridad y Privacidad

- **100% local**: El programa no realiza ninguna conexión a internet
- **Sin telemetría**: No se envían datos a ningún servidor
- **Código abierto**: Puedes auditar todo el código fuente

---

## 📚 Créditos y referencias técnicas

- Algoritmo de desencriptación: [zhangyoufu/unifi-backup-decrypt](https://github.com/zhangyoufu/unifi-backup-decrypt)
- Formato de backup UniFi: AES-128-CBC, clave `bcyangkmluohmars`, IV `ubntenterpriseap`
- Base de datos interna: MongoDB dump (BSON) comprimido con gzip

---

*Desarrollado por Ing. Walter Rodríguez para facilitar la gestión y auditoría de redes Ubiquiti.*
