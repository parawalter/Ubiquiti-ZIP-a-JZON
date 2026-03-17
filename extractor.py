"""
Autor: Ing. Walter Rodríguez
Fecha: 17/03/2026
Descripción: Lógica de extracción y conversión de archivos .unf de UniFi a JSON.
             Algoritmo oficial de desencriptación AES-128-CBC NoPadding.
             La extracción forzada usa zlib.decompressobj con unused_data para detectar
             automáticamente el fin de cada stream deflate sin necesitar el comp_size.
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

ZIP_LOCAL_HEADER = b'PK\x03\x04'
ZIP_DATA_DESC    = b'PK\x07\x08'


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
    # Extracción forzada: escanea Local File Headers sin depender del
    # Central Directory (que queda corrupto con AES NoPadding).
    # Para Deflate usa zlib.decompressobj + unused_data → detecta
    # automáticamente el fin del stream, sin importar comp_size.
    # ------------------------------------------------------------------
    def _force_extract(self, zip_bytes, extract_path):
        data = zip_bytes
        pos  = 0
        extracted = []
        failed    = []

        while pos < len(data) - 4:
            # Buscar próximo Local File Header
            idx = data.find(ZIP_LOCAL_HEADER, pos)
            if idx == -1:
                break
            pos = idx

            if pos + 30 > len(data):
                break

            # Parsear header (30 bytes fijos)
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

            file_data_start = pos + 30 + fname_len + extra_len

            # Leer nombre del archivo
            try:
                fname = data[pos + 30: pos + 30 + fname_len].decode('utf-8', errors='replace')
            except Exception:
                pos = file_data_start + 1
                continue

            # Ignorar entradas de directorio
            if fname.endswith('/') or fname.endswith('\\'):
                pos = file_data_start
                continue

            # Extraer datos según método de compresión
            try:
                if method == 0:
                    # ── Stored (sin compresión) ──────────────────────────────
                    if comp_size > 0:
                        file_content = data[file_data_start: file_data_start + comp_size]
                        pos_after = file_data_start + comp_size
                    else:
                        # Data Descriptor: buscar siguiente PK header
                        next_pk = data.find(b'PK', file_data_start + 1)
                        end = next_pk if next_pk != -1 else len(data)
                        file_content = data[file_data_start:end]
                        pos_after = end

                elif method == 8:
                    # ── Deflate ──────────────────────────────────────────────
                    # Usar decompressobj: unused_data indica exactamente
                    # cuántos bytes vienen DESPUÉS del fin del stream deflate.
                    # Con esto NO necesitamos conocer comp_size de antemano.
                    dobj = zlib.decompressobj(-15)
                    try:
                        file_content = dobj.decompress(data[file_data_start:])
                        file_content += dobj.flush()
                    except zlib.error:
                        # Si falla en mitad, tomar lo que se pudo descomprimir
                        file_content = dobj.decompress(data[file_data_start:], max_length=10*1024*1024)
                    
                    # Calcular cuántos bytes consumió el depresor
                    actual_comp = len(data) - file_data_start - len(dobj.unused_data)
                    pos_after = file_data_start + max(actual_comp, 1)

                else:
                    self.log(f"  Método de compresión {method} no soportado: {fname}")
                    pos = file_data_start + (comp_size if comp_size > 0 else 1)
                    continue

                if not file_content:
                    self.log(f"  Archivo vacío ignorado: {fname}")
                    pos = pos_after
                    continue

                # Escribir al disco
                out_path = os.path.join(extract_path, fname.replace('/', os.sep))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'wb') as f:
                    f.write(file_content)

                extracted.append(fname)
                self.log(f"  Extraído: {fname} ({len(file_content):,} bytes)")
                pos = pos_after

            except Exception as e:
                self.log(f"  Aviso al descomprimir '{fname}': {e}")
                failed.append(fname)
                # Avanzar para no quedar en bucle infinito
                pos = file_data_start + (comp_size if comp_size > 0 else 1)

        return extracted, failed

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

            # ── Paso 1: ¿Ya es un ZIP? ────────────────────────────────────
            if raw_data[:4] == ZIP_LOCAL_HEADER:
                self.log("Archivo ZIP detectado directamente (sin encriptación).")
                zip_bytes = raw_data
            else:
                # ── Paso 2: Desencriptar AES-128-CBC NoPadding ────────────
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

                # ── Paso 3: Localizar inicio del ZIP ─────────────────────
                offset = decrypted.find(ZIP_LOCAL_HEADER)
                if offset == -1:
                    raise Exception(
                        "No se encontró un ZIP válido tras la desencriptación.\n"
                        "Verifica que el archivo sea un backup válido de UniFi Network."
                    )
                if offset > 0:
                    self.log(f"Ajustando offset del ZIP: {offset} bytes omitidos.")
                zip_bytes = decrypted[offset:]

            self.update_progress(0.3)

            # ── Paso 4: Extraer contenido del ZIP ─────────────────────────
            extract_path = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_path, exist_ok=True)
            self.log("Extrayendo contenido del backup...")

            # Intentar primero con zipfile estándar
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                self.log("Extracción ZIP estándar exitosa.")
            except Exception as e:
                self.log(f"ZIP estándar falló ({e}). Usando extracción forzada...")
                extracted, failed = self._force_extract(zip_bytes, extract_path)

                if not extracted and not failed:
                    raise Exception("No se encontraron entradas de archivo en el backup.")
                if not extracted:
                    raise Exception(
                        f"Se encontraron {len(failed)} archivos pero ninguno pudo extraerse.\n"
                        f"Archivos fallidos: {', '.join(failed)}"
                    )
                self.log(f"Extracción forzada: {len(extracted)} archivos OK, {len(failed)} con aviso.")

            self.update_progress(0.5)

            # ── Paso 5: Localizar la base de datos (db.gz) ────────────────
            db_gz_path = None
            db_bson_path = os.path.join(temp_dir, "db.bson")

            self.log("Buscando base de datos...")
            # Prioridad: db.gz → db → cualquier .gz en la raíz
            for root, dirs, files in os.walk(extract_path):
                for candidate in ["db.gz", "db"]:
                    if candidate in files:
                        db_gz_path = os.path.join(root, candidate)
                        self.log(f"Base de datos encontrada: {candidate}")
                        break
                if db_gz_path:
                    break

            # Si no hay db.gz exacto, buscar cualquier .gz que pueda contener BSON
            if not db_gz_path:
                for root, dirs, files in os.walk(extract_path):
                    for f in files:
                        if f.endswith('.gz') and not f.startswith('db_stat'):
                            db_gz_path = os.path.join(root, f)
                            self.log(f"Usando archivo alternativo: {f}")
                            break
                    if db_gz_path:
                        break

            if not db_gz_path:
                found = []
                for root, dirs, files in os.walk(extract_path):
                    for f in files:
                        found.append(os.path.relpath(os.path.join(root, f), extract_path))
                raise Exception(
                    f"No se encontró la base de datos (db.gz o db) dentro del backup.\n"
                    f"Archivos disponibles: {', '.join(found) if found else 'ninguno'}"
                )

            # ── Paso 6: Descomprimir db.gz → BSON ────────────────────────
            if db_gz_path.endswith(".gz"):
                self.log("Descomprimiendo db.gz...")
                with gzip.open(db_gz_path, 'rb') as f_in:
                    with open(db_bson_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(db_gz_path, db_bson_path)

            self.update_progress(0.7)

            # ── Paso 7: BSON → JSON ───────────────────────────────────────
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
