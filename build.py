"""
Autor: Ing. Walter Rodríguez
Fecha: 16/02/2026
Descripción: Script para generar el ejecutable .exe de UniFi UNF Extractor usando PyInstaller.
"""

import PyInstaller.__main__
import os
import sys

def build():
    # Nombre de la aplicación
    app_name = "UniFi_UNF_Extractor"
    
    # Archivo principal
    main_script = "main.py"
    
    # Obtener ruta de dependencias de customtkinter (necesario para PyInstaller)
    import customtkinter
    ctk_path = os.path.dirname(customtkinter.__file__)
    
    # Argumentos de PyInstaller
    args = [
        main_script,
        f"--name={app_name}",
        "--onefile",
        "--windowed",
        f"--add-data={ctk_path};customtkinter/",
        "--collect-all=tkinterdnd2",
        "--clean",
    ]
    
    print(f"Iniciando compilación de {app_name}...")
    PyInstaller.__main__.run(args)
    print("¡Compilación finalizada! Revisa la carpeta 'dist'.")

if __name__ == "__main__":
    try:
        build()
    except ImportError:
        print("Error: PyInstaller no está instalado. Ejecuta: pip install pyinstaller")
    except Exception as e:
        print(f"Error durante el build: {e}")
