"""
Autor: Ing. Walter Rodríguez
Fecha: 17/03/2026
Descripción: Lógica de extracción y conversión de archivos .unf de UniFi a JSON.
             Algoritmo oficial de desencriptación:
               - Clave AES-128-CBC: bcyangkmluohmars (hex: 626379616e676b6d6c756f686d617273)
               - IV: ubntenterpriseap (hex: 75626e74656e74657270726973656170)
               - Modo: NoPadding (el ZIP resultante puede estar malformado, se repara buscando PK magic)
             Fuente: https://github.com/zhangyoufu/unifi-backup-decrypt
"""

import os
import io
import zipfile
import gzip
import shutil
import json
import tempfile
from bson import decode_all
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Magic bytes que identifican el inicio de un archivo ZIP
ZIP_MAGIC = b'PK\x03\x04'

class UnifiExtractor:
    def __init__(self, progress_callback=None, log_callback=None):
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        # Clave y IV reales de Ubiquiti, extraídos del código fuente oficial.
        # Fuente: https://github.com/zhangyoufu/unifi-backup-decrypt
        # Equivalentes hex: K=626379616e676b6d6c756f686d617273  iv=75626e74656e74657270726973656170
        self.key = b"bcyangkmluohmars"   # 16 bytes -> AES-128
        self.iv_bytes = b"ubntenterpriseap"  # 16 bytes de IV real

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def update_progress(self, value):
        if self.progress_callback:
            self.progress_callback(value)

    def _repair_zip(self, raw_bytes):
        """
        Tras la desencriptación AES/CBC/NoPadding el ZIP puede quedar malformado
        (bytes de relleno al final o cabecera desplazada). 
        Esta función busca el magic PK\\x03\\x04 y recorta desde ahí.
        Equivale al 'zip -FF' del script oficial de bash.
        """
        offset = raw_bytes.find(ZIP_MAGIC)
        if offset == -1:
            return None  # No es un ZIP válido en absoluto
        if offset > 0:
            self.log(f"ZIP malformado detectado. Reparando desde offset {offset}...")
        return raw_bytes[offset:]

    def extract(self, unf_path):
        temp_dir = tempfile.mkdtemp()
        try:
            filename = os.path.basename(unf_path)
            output_json = os.path.join(os.path.dirname(unf_path), "config.json")

            self.log(f"Iniciando procesamiento de: {filename}")
            self.update_progress(0.1)

            decrypted_zip = os.path.join(temp_dir, "backup.zip")
            self.log("Analizando archivo...")

            with open(unf_path, 'rb') as f:
                raw_data = f.read()

            zip_bytes = None

            # --- Paso 1: Detectar si ya es un ZIP válido ---
            if raw_data[:4] == ZIP_MAGIC:
                self.log("Archivo ZIP detectado directamente (sin encriptación).")
                zip_bytes = raw_data

            else:
                # --- Paso 2: Desencriptar con clave oficial de Ubiquiti ---
                self.log("Desencriptando .unf con clave oficial Ubiquiti (AES-128-CBC, NoPadding)...")
                try:
                    cipher = Cipher(
                        algorithms.AES(self.key),
                        modes.CBC(self.iv_bytes),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted_bytes = decryptor.update(raw_data) + decryptor.finalize()
                    self.log("Desencriptación AES completada.")
                except Exception as e:
                    raise Exception(f"Fallo en la desencriptación AES: {str(e)}")

                # --- Paso 3: Reparar ZIP malformado (equivale a 'zip -FF') ---
                zip_bytes = self._repair_zip(decrypted_bytes)
                if zip_bytes is None:
                    raise Exception(
                        "El archivo desencriptado no contiene un ZIP válido.\n"
                        "Asegúrate de que sea un backup válido de UniFi Network (.unf o .zip)."
                    )
                self.log("¡ZIP reparado y listo para extraer!")

            # Guardar ZIP reparado en disco
            with open(decrypted_zip, 'wb') as f:
                f.write(zip_bytes)

            self.update_progress(0.3)

            # --- Paso 4: Extraer contenido del ZIP ---
            extract_path = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_path, exist_ok=True)
            self.log("Extrayendo contenido del backup...")

            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            except zipfile.BadZipFile as e:
                raise Exception(f"No se pudo extraer el ZIP incluso después de repararlo: {str(e)}")

            self.update_progress(0.5)

            # --- Paso 5: Localizar db.gz (base de datos BSON) ---
            db_gz_path = None
            db_bson_path = os.path.join(temp_dir, "db.bson")

            self.log("Buscando base de datos (db.gz) dentro del backup...")
            for root, dirs, files in os.walk(extract_path):
                if "db.gz" in files:
                    db_gz_path = os.path.join(root, "db.gz")
                    break
                # Algunos backups incluyen el BSON sin comprimir
                if "db" in files:
                    db_gz_path = os.path.join(root, "db")
                    self.log("Detectado archivo db (BSON) sin compresión gz.")
                    break

            if not db_gz_path:
                # Listar lo que hay para ayudar en el diagnóstico
                found = []
                for root, dirs, files in os.walk(extract_path):
                    for f in files:
                        found.append(os.path.relpath(os.path.join(root, f), extract_path))
                raise Exception(
                    f"No se encontró el archivo de base de datos (db.gz o db) dentro del backup.\n"
                    f"Archivos encontrados: {', '.join(found) if found else 'ninguno'}"
                )

            self.log(f"Base de datos encontrada: {os.path.basename(db_gz_path)}")

            # --- Paso 6: Descomprimir db.gz -> BSON ---
            if db_gz_path.endswith(".gz"):
                self.log("Descomprimiendo db.gz...")
                with gzip.open(db_gz_path, 'rb') as f_in:
                    with open(db_bson_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(db_gz_path, db_bson_path)

            self.update_progress(0.7)

            # --- Paso 7: Decodificar BSON a JSON ---
            self.log("Convirtiendo BSON a JSON...")
            with open(db_bson_path, 'rb') as f:
                data = decode_all(f.read())

            # Serializador para tipos de MongoDB no compatibles con JSON estándar
            def custom_serializer(obj):
                from bson import ObjectId
                from datetime import datetime
                if isinstance(obj, ObjectId):
                    return str(obj)
                if isinstance(obj, datetime):
                    return obj.isoformat()
                return str(obj)

            with open(output_json, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=custom_serializer, ensure_ascii=False)

            self.update_progress(1.0)
            self.log(f"¡Éxito! Archivo guardado en: {output_json}")
            return output_json

        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            raise e
        finally:
            # Limpiar temporales siempre al finalizar
            shutil.rmtree(temp_dir, ignore_errors=True)
