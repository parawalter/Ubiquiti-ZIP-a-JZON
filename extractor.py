"""
Autor: Ing. Walter Rodríguez
Fecha: 17/03/2026
Descripción: Lógica de extracción y conversión de archivos .unf de UniFi a JSON.
             Algoritmo oficial de desencriptación:
               - Clave AES-128-CBC: bcyangkmluohmars
               - IV: ubntenterpriseap
               - Modo: NoPadding → ZIP puede tener Central Directory corrupto.
             Se implementa extracción forzada escaneando Local File Headers (PK\x03\x04),
             equivalente al 'zip -FF' del script bash oficial.
             Fuente: https://github.com/zhangyoufu/unifi-backup-decrypt
"""

import os
import io
import struct
import zipfile
import zlib
import gzip
import shutil
import json
import tempfile
from bson import decode_all
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Firmas ZIP conocidas
ZIP_LOCAL_HEADER  = b'PK\x03\x04'  # Local file header
ZIP_EOCD          = b'PK\x05\x06'  # End of Central Directory


class UnifiExtractor:
    def __init__(self, progress_callback=None, log_callback=None):
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        # Clave y IV reales de Ubiquiti.
        # Fuente: https://github.com/zhangyoufu/unifi-backup-decrypt
        self.key      = b"bcyangkmluohmars"   # 16 bytes → AES-128
        self.iv_bytes = b"ubntenterpriseap"   # 16 bytes de IV real

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def update_progress(self, value):
        if self.progress_callback:
            self.progress_callback(value)

    # ------------------------------------------------------------------
    # Extracción forzada: escanea Local File Headers sin Central Directory
    # Equivale al comportamiento de 'zip -FF' en el script bash oficial
    # ------------------------------------------------------------------
    def _force_extract(self, zip_bytes, extract_path):
        """
        Parsea manualmente los Local File Headers (PK\\x03\\x04) del ZIP,
        ignorando el Central Directory (que puede estar corrupto con NoPadding).
        Soporta almacenamiento (method=0) y deflate (method=8).
        """
        data = zip_bytes
        pos  = 0
        extracted = []

        while pos < len(data) - 4:
            # Buscar siguiente Local File Header
            idx = data.find(ZIP_LOCAL_HEADER, pos)
            if idx == -1:
                break
            pos = idx

            # Verificar que hay suficientes bytes para leer el header (30 bytes mínimo)
            if pos + 30 > len(data):
                break

            # Parsear campos del Local File Header
            # Estructura: sig(4) ver(2) flag(2) method(2) mtime(2) mdate(2)
            #             crc32(4) comp_size(4) uncomp_size(4) fname_len(2) extra_len(2)
            try:
                (sig, ver_needed, flags, method,
                 mod_time, mod_date, crc32,
                 comp_size, uncomp_size,
                 fname_len, extra_len) = struct.unpack_from('<4sHHHHHIIIHH', data, pos)
            except struct.error:
                pos += 1
                continue

            if sig != ZIP_LOCAL_HEADER:
                pos += 1
                continue

            header_end = pos + 30 + fname_len + extra_len

            # Leer nombre del archivo
            try:
                fname = data[pos + 30: pos + 30 + fname_len].decode('utf-8', errors='replace')
            except Exception:
                pos += 1
                continue

            # Ignorar entradas de directorio
            if fname.endswith('/') or fname.endswith('\\'):
                pos = header_end
                continue

            # Si comp_size == 0 y hay Data Descriptor (flag bit 3), estimar tamaño
            file_data_start = header_end
            if comp_size == 0 and (flags & 0x08):
                # Buscar el próximo Local File Header o EOCD para calcular el tamaño
                next_pk = data.find(b'PK', file_data_start + 1)
                if next_pk == -1:
                    comp_size = len(data) - file_data_start
                else:
                    comp_size = next_pk - file_data_start
                    # Descontar posible Data Descriptor (12 o 16 bytes: PK\x07\x08 + crc + comp + uncomp)
                    if data[next_pk:next_pk+4] == b'PK\x07\x08':
                        comp_size = max(0, comp_size - 16)

            file_data_end = file_data_start + comp_size
            if file_data_end > len(data):
                file_data_end = len(data)

            compressed_data = data[file_data_start:file_data_end]

            # Descomprimir según el método
            try:
                if method == 0:   # Store (sin compresión)
                    file_content = compressed_data
                elif method == 8: # Deflate
                    file_content = zlib.decompress(compressed_data, -15)
                else:
                    self.log(f"  Método de compresión {method} no soportado para: {fname}")
                    pos = file_data_end
                    continue
            except Exception as e:
                self.log(f"  Aviso al descomprimir '{fname}': {e}")
                pos = file_data_end
                continue

            # Escribir el archivo extraído
            out_path = os.path.join(extract_path, fname.replace('/', os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(file_content)

            extracted.append(fname)
            self.log(f"  Extraído: {fname} ({len(file_content)} bytes)")
            pos = file_data_end

        return extracted

    def extract(self, unf_path):
        temp_dir = tempfile.mkdtemp()
        try:
            filename = os.path.basename(unf_path)
            output_json = os.path.join(os.path.dirname(unf_path), "config.json")

            self.log(f"Iniciando procesamiento de: {filename}")
            self.update_progress(0.1)

            with open(unf_path, 'rb') as f:
                raw_data = f.read()

            zip_bytes = None

            # --- Paso 1: ¿Ya es un ZIP? ---
            if raw_data[:4] == ZIP_LOCAL_HEADER:
                self.log("Archivo ZIP detectado directamente (sin encriptación).")
                zip_bytes = raw_data
            else:
                # --- Paso 2: Desencriptar AES-128-CBC NoPadding ---
                self.log("Desencriptando .unf con clave oficial Ubiquiti (AES-128-CBC)...")
                try:
                    cipher = Cipher(
                        algorithms.AES(self.key),
                        modes.CBC(self.iv_bytes),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(raw_data) + decryptor.finalize()
                    self.log("Desencriptación AES completada.")
                except Exception as e:
                    raise Exception(f"Fallo en la desencriptación AES: {e}")

                # --- Paso 3: Buscar inicio del ZIP (PK magic bytes) ---
                offset = decrypted.find(ZIP_LOCAL_HEADER)
                if offset == -1:
                    raise Exception(
                        "No se encontró un ZIP válido tras la desencriptación.\n"
                        "Verifica que el archivo sea un backup de UniFi Network (.unf)."
                    )
                if offset > 0:
                    self.log(f"Ajustando offset del ZIP: {offset} bytes.")
                zip_bytes = decrypted[offset:]

            self.update_progress(0.3)

            # --- Paso 4: Extraer contenido ---
            extract_path = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_path, exist_ok=True)
            self.log("Extrayendo contenido del backup...")

            # Intentar primero con zipfile estándar
            extracted_ok = False
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                extracted_ok = True
                self.log("Extracción ZIP estándar exitosa.")
            except (zipfile.BadZipFile, Exception) as e:
                self.log(f"ZIP estándar falló ({e}). Usando extracción forzada (modo zip -FF)...")
                extracted = self._force_extract(zip_bytes, extract_path)
                if not extracted:
                    raise Exception("La extracción forzada no encontró ningún archivo en el backup.")
                extracted_ok = True

            if not extracted_ok:
                raise Exception("No se pudo extraer el contenido del backup.")

            self.update_progress(0.5)

            # --- Paso 5: Localizar db.gz ---
            db_gz_path = None
            db_bson_path = os.path.join(temp_dir, "db.bson")

            self.log("Buscando base de datos (db.gz)...")
            for root, dirs, files in os.walk(extract_path):
                if "db.gz" in files:
                    db_gz_path = os.path.join(root, "db.gz")
                    break
                if "db" in files:
                    db_gz_path = os.path.join(root, "db")
                    self.log("Detectado archivo db (BSON) sin compresión gz.")
                    break

            if not db_gz_path:
                found = []
                for root, dirs, files in os.walk(extract_path):
                    for fname in files:
                        found.append(os.path.relpath(os.path.join(root, fname), extract_path))
                raise Exception(
                    f"No se encontró db.gz dentro del backup.\n"
                    f"Archivos encontrados: {', '.join(found) if found else 'ninguno'}"
                )

            self.log(f"Base de datos encontrada: {os.path.basename(db_gz_path)}")

            # --- Paso 6: Descomprimir db.gz → BSON ---
            if db_gz_path.endswith(".gz"):
                self.log("Descomprimiendo db.gz...")
                with gzip.open(db_gz_path, 'rb') as f_in:
                    with open(db_bson_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(db_gz_path, db_bson_path)

            self.update_progress(0.7)

            # --- Paso 7: BSON → JSON ---
            self.log("Convirtiendo BSON a JSON...")
            with open(db_bson_path, 'rb') as f:
                data = decode_all(f.read())

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
            self.log(f"¡Éxito! JSON guardado en: {output_json}")
            return output_json

        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            raise e
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
