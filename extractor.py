"""
Autor: Ing. Walter Rodríguez
Fecha: 16/02/2026
Descripción: Lógica de extracción y conversión de archivos .unf de UniFi a JSON.
"""

import os
import zipfile
import gzip
import shutil
import json
import tempfile
from bson import decode_all
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import hashlib

class UnifiExtractor:
    def __init__(self, progress_callback=None, log_callback=None):
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        # Clave estándar para backups de UniFi
        self.key = "ubntrocks!"
        self.iv_bytes = b'\x00' * 16

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def update_progress(self, value):
        if self.progress_callback:
            self.progress_callback(value)

    def extract(self, unf_path):
        temp_dir = tempfile.mkdtemp()
        try:
            filename = os.path.basename(unf_path)
            output_json = os.path.join(os.path.dirname(unf_path), "config.json")
            
            self.log(f"Iniciando procesamiento de: {filename}")
            self.update_progress(0.1)

            decrypted_zip = os.path.join(temp_dir, "backup.zip")
            self.log("Analizando archivo UNF...")
            
            with open(unf_path, 'rb') as f:
                encrypted_data = f.read()

            success = False
            last_error = ""

            # 1. Verificar si es ZIP directo
            if zipfile.is_zipfile(unf_path):
                self.log("Archivo ZIP detectado (sin encriptación).")
                with open(decrypted_zip, 'wb') as f:
                    f.write(encrypted_data)
                success = True
            else:
                try:
                    self.log("Desencriptando usando método nativo AES...")
                    
                    # Derivación de clave UniFi: MD5 de "ubntrocks!"
                    key_hash = hashlib.md5(self.key.encode()).digest() # 16 bytes
                    
                    # Datos a desencriptar (saltar cabecera 'Salted__' si existe)
                    data_to_decrypt = encrypted_data
                    if encrypted_data.startswith(b'Salted__'):
                        self.log("Detectado formato Salted de OpenSSL.")
                        data_to_decrypt = encrypted_data[16:]

                    # Probar AES-128-CBC (clave 16 bytes)
                    cipher = Cipher(algorithms.AES(key_hash), modes.CBC(self.iv_bytes), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_bytes = decryptor.update(data_to_decrypt) + decryptor.finalize()
                    
                    with open(decrypted_zip, 'wb') as f:
                        f.write(decrypted_bytes)
                    
                    if zipfile.is_zipfile(decrypted_zip):
                        success = True
                        self.log("¡Desencriptación exitosa (128-bit)!")
                    else:
                        # Probar AES-256-CBC (clave 32 bytes = MD5 duplicado, común en versiones viejas)
                        key_hash_32 = key_hash * 2
                        cipher = Cipher(algorithms.AES(key_hash_32), modes.CBC(self.iv_bytes), backend=default_backend())
                        decryptor = cipher.decryptor()
                        decrypted_bytes = decryptor.update(data_to_decrypt) + decryptor.finalize()
                        
                        with open(decrypted_zip, 'wb') as f:
                            f.write(decrypted_bytes)
                        
                        if zipfile.is_zipfile(decrypted_zip):
                            success = True
                            self.log("¡Desencriptación exitosa (256-bit)!")
                        else:
                            raise Exception("Formato de encriptación no reconocido.")

                except Exception as e:
                    last_error = str(e)
                    success = False

            if not success:
                raise Exception(f"No se pudo abrir el backup.\nError: {last_error}")

            self.update_progress(0.3)
            self.log("Archivo desencriptado correctamente.")

            # 2. Extraer ZIP
            extract_path = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_path, exist_ok=True)
            self.log("Extrayendo contenido del backup...")
            try:
                with zipfile.ZipFile(decrypted_zip, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            except zipfile.BadZipFile:
                # Si no es un ZIP, tal vez es que db.gz está directamente en la raíz tras desencriptar
                self.log("Aviso: El archivo no es un ZIP estándar, intentando búsqueda directa...")
                # En algunos casos el .unf desencriptado es directamente el db.gz
                if not decrypted_zip.endswith('.gz'):
                    potential_gz = decrypted_zip + ".gz"
                    os.rename(decrypted_zip, potential_gz)
                    decrypted_zip = potential_gz
            
            self.update_progress(0.5)

            # 3. Buscar y gunzip db.gz (o db directamente)
            db_gz_path = None
            db_bson_path = os.path.join(temp_dir, "db.bson")
            
            # Buscar db.gz en todo el árbol extraído
            for root, dirs, files in os.walk(extract_path):
                if "db.gz" in files:
                    db_gz_path = os.path.join(root, "db.gz")
                    break
            
            # Si no se encontró db.gz, buscar archivos .bson directos (algunas herramientas los dan así)
            if not db_gz_path:
                for root, dirs, files in os.walk(extract_path):
                    if "db" in files and not files[0].endswith(".gz"):
                        # Podría ser el bson directo
                        db_gz_path = os.path.join(root, "db")
                        self.log("Detectado archivo db (BSON) directo.")
                        break

            if not db_gz_path and zipfile.is_zipfile(unf_path):
                # Caso especial: el ZIP original ya tiene el db.gz
                # Esto ya debería estar cubierto por la extracción, pero por si acaso
                pass

            if not db_gz_path:
                 raise Exception("No se encontró el archivo de base de datos (db.gz o db) dentro del backup.")

            self.log(f"Procesando base de datos: {os.path.basename(db_gz_path)}")
            
            if db_gz_path.endswith(".gz"):
                with gzip.open(db_gz_path, 'rb') as f_in:
                    with open(db_bson_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(db_gz_path, db_bson_path)
            
            self.update_progress(0.7)

            # 4. Decodificar BSON a JSON
            self.log("Convirtiendo datos BSON a JSON...")
            with open(db_bson_path, 'rb') as f:
                data = decode_all(f.read())
            
            # Limpiar tipos de datos de MongoDB para JSON (como ObjectId)
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
            # 5. Limpiar temporales
            shutil.rmtree(temp_dir, ignore_errors=True)
