# UniFi UNF/ZIP to JSON Extractor 🚀

**Autor:** Ing. Walter Rodríguez  
**Fecha:** 16/02/2026

## 📝 ¿Para qué sirve?
Esta aplicación es una herramienta especializada diseñada para administradores de red que trabajan con ecosistemas **Ubiquiti UniFi**. Su función principal es extraer y convertir los archivos de respaldo de UniFi (con extensión `.unf` o contenido dentro de un `.zip`) a un formato **JSON** estructurado y legible.

Normalmente, los backups de UniFi están en un formato binario comprimido (BSON/MongoDB dump) que no es fácil de leer sin restaurarlo en un controlador. Esta herramienta elimina esa barrera, permitiendo visualizar la configuración completa en segundos.

---

## ⚙️ Funcionamiento
1.  **Carga Sencilla**: Soporta **Drag & Drop** (arrastrar y soltar). Solo arrastra tu archivo `.unf` o `.zip` a la interfaz.
2.  **Extracción Automática**: El sistema identifica los archivos de configuración dentro del respaldo.
3.  **Conversión BSON a JSON**: Procesa las bases de datos internas (como `configuration.bson`) y las transforma en texto plano estructurado.
4.  **Generación de Salida**: Crea un archivo `.json` en la misma carpeta del archivo original, organizado de forma jerárquica y con indentación ("Pretty Print").

---

## ✨ Ventajas de usarlo
*   **Portabilidad**: No necesitas instalar un controlador UniFi para revisar una configuración vieja.
*   **Rapidez**: Conversión instantánea sin procesos complejos de restauración.
*   **Interfaz Moderna**: Diseñada con una estética SaaS premium, oscura y minimalista.
*   **Independencia**: Funciona localmente en tu PC sin enviar datos a la nube (Privacidad total).

---

## 🤖 El Poder del JSON con Inteligencia Artificial (IA)
Una de las mayores ventajas de obtener un JSON estructurado es su interoperabilidad con modelos como **ChatGPT, Claude o Gemini**. Al cargar este JSON en una IA, puedes obtener asistencia técnica avanzada:

1.  **Auditoría de Seguridad**: Puedes preguntarle a la IA: *"Analiza este JSON y dime si hay puertos abiertos vulnerables o configuraciones de firewall inseguras"*.
2.  **Documentación Automática**: *"Genera una tabla en Markdown con todos los SSIDs, VLANs y sus respectivas subredes basadas en este archivo"*.
3.  **Troubleshooting (Solución de Problemas)**: Si una red falla, puedes comparar JSONs de diferentes fechas: *"Dime qué cambió en la configuración de las VLANs entre estos dos archivos"*.
4.  **Generación de Scripts**: *"Crea un script de Python para validar que todos los puntos de acceso tengan activado el Band Steering según los datos del JSON"*.
5.  **Optimización**: La IA puede sugerir canales WiFi menos saturados o configuraciones de potencia basadas en la lista de dispositivos detectados en el respaldo.

---

## 🚀 Instalación y Uso (Desarrolladores)
1. Clona el repositorio.
2. Instala dependencias: `pip install -r requirements.txt`.
3. Ejecuta `python main.py` o usa el ejecutable en la carpeta `dist`.

### ⚠️ Solución de problemas comunes
Si ves el error: `ImportError: cannot import name 'decode_all' from 'bson'`, es debido a un conflicto entre los paquetes `bson` y `pymongo`. Para solucionarlo, ejecuta estos comandos en tu terminal:

```powershell
pip uninstall bson pymongo
pip install pymongo
```

---
*Desarrollado para facilitar la gestión de redes Ubiquiti con tecnología moderna.*
