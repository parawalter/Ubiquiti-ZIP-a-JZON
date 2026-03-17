"""
Autor: Ing. Walter Rodríguez
Fecha: 17/03/2026
Descripción: Interfaz gráfica moderna para UniFi UNF Extractor usando customtkinter.
             Actualización: Integrado soporte nativo para .unf con clave AES oficial de Ubiquiti.
             Fuente de clave: https://github.com/zhangyoufu/unifi-backup-decrypt
"""

import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox, Canvas
from extractor import UnifiExtractor

# Configuración de apariencia
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. Definir variables básicas
        self.width = 750
        self.height = 650
        self.version = "v1.0.0"
        self.author = "Ing. Walter Rodríguez"
        self.description = "Esta herramienta permite extraer y convertir archivos de backup (.unf) de UniFi Network a un formato JSON legible, facilitando la auditoría y migración de configuraciones de red, redes WiFi y dispositivos."
        self.selected_file = None  # Archivo seleccionado por el usuario

        # 2. Configurar ventana y centrar
        self.title(f"UniFi UNF to JSON Extractor - {self.version}")
        self.center_window()
        self.resizable(True, True)

        # 3. Inicializar extractor
        self.extractor = UnifiExtractor(
            progress_callback=self.update_progress,
            log_callback=self.add_log
        )

        # 4. Construir UI
        self.setup_ui()

    def center_window(self):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width / 2) - (self.width / 2)
        y = (screen_height / 2) - (self.height / 2)
        self.geometry(f'{self.width}x{self.height}+{int(x)}+{int(y)}')

    def setup_ui(self):
        # Configuración de grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Contenedor Logotipo/Branding
        self.branding_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.branding_frame.grid(row=0, column=0, padx=20, pady=(20, 0))
        
        # Dibujar un logo moderno usando Canvas (vanguardista y tecnológico)
        self.logo_canvas = Canvas(self.branding_frame, width=80, height=80, bg="#242424", highlightthickness=0)
        self.logo_canvas.pack()
        # Escudo/Círculo exterior
        self.logo_canvas.create_oval(10, 10, 70, 70, outline="#3B8ED0", width=3)
        # Símbolo central (Estilo Red/Conexión)
        self.logo_canvas.create_arc(20, 25, 60, 65, start=45, extent=90, outline="#3B8ED0", width=4, style="arc")
        self.logo_canvas.create_arc(30, 35, 50, 55, start=45, extent=90, outline="#5DADE2", width=4, style="arc")
        self.logo_canvas.create_oval(35, 45, 45, 55, fill="#5DADE2", outline="")

        # Encabezado
        self.header_label = ctk.CTkLabel(
            self, 
            text="UniFi UNF Extractor", 
            font=ctk.CTkFont(size=32, weight="bold")
        )
        self.header_label.grid(row=1, column=0, padx=20, pady=(10, 5))

        # Descripción
        self.desc_label = ctk.CTkLabel(
            self,
            text=self.description,
            font=ctk.CTkFont(size=12),
            wraplength=650,
            text_color="#BBBBBB"
        )
        self.desc_label.grid(row=2, column=0, padx=40, pady=(0, 20))


        # Zona de Selección (Simplificada)
        self.drop_frame = ctk.CTkFrame(self, border_width=2, border_color="#3B8ED0", fg_color="#2B2B2B")
        self.drop_frame.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")
        self.drop_frame.grid_columnconfigure(0, weight=1)
        self.drop_frame.grid_rowconfigure(0, weight=1)

        self.drop_label = ctk.CTkLabel(
            self.drop_frame, 
            text="Selecciona tu archivo .unf o .zip de UniFi",
            font=ctk.CTkFont(size=14)
        )
        self.drop_label.grid(row=0, column=0, padx=20, pady=40)

        # Botones de acción
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.grid(row=5, column=0, padx=20, pady=10)

        self.select_button = ctk.CTkButton(
            self.button_frame, 
            text="Seleccionar Archivo .unf / .zip", 
            command=self.browse_file,
            width=200,
            height=40,
            font=ctk.CTkFont(weight="bold")
        )
        self.select_button.grid(row=0, column=0, padx=10)

        self.convert_button = ctk.CTkButton(
            self.button_frame, 
            text="Convertir a JSON", 
            command=self.start_conversion,
            state="disabled",
            fg_color="#2ECC71",
            hover_color="#27AE60",
            width=200,
            height=40,
            font=ctk.CTkFont(weight="bold")
        )
        self.convert_button.grid(row=0, column=1, padx=10)

        # Información del archivo
        self.info_label = ctk.CTkLabel(self, text="Ningún archivo seleccionado", font=ctk.CTkFont(size=12, slant="italic"))
        self.info_label.grid(row=6, column=0, padx=20, pady=5)

        # Barra de progreso
        self.progress_bar = ctk.CTkProgressBar(self, width=600)
        self.progress_bar.grid(row=7, column=0, padx=20, pady=(10, 10))
        self.progress_bar.set(0)

        # Caja de logs
        self.log_box = ctk.CTkTextbox(self, height=120, font=ctk.CTkFont(family="Consolas", size=11))
        self.log_box.grid(row=8, column=0, padx=20, pady=(0, 10), sticky="nsew")
        self.log_box.configure(state="disabled")

        # Footer (Autor y Versión)
        self.footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.footer_frame.grid(row=9, column=0, padx=20, pady=(0, 15), sticky="ew")
        self.footer_frame.grid_columnconfigure(0, weight=1)

        self.author_label = ctk.CTkLabel(
            self.footer_frame, 
            text=f"Autor: {self.author}", 
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#5DADE2"
        )
        self.author_label.grid(row=0, column=0, sticky="w", padx=5)

        self.version_label = ctk.CTkLabel(
            self.footer_frame, 
            text=f"Versión {self.version}", 
            font=ctk.CTkFont(size=11),
            text_color="#888888"
        )
        self.version_label.grid(row=0, column=1, sticky="e", padx=5)

    # Eliminado handle_drop por incompatibilidad de librería

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Seleccionar backup de UniFi",
            filetypes=[
                ("Archivos de backup UniFi", "*.zip *.unf"),
                ("Archivo ZIP", "*.zip"),
                ("Archivo UNF", "*.unf"),
                ("Todos los archivos", "*.*")
            ]
        )
        if file_path:
            self.set_selected_file(file_path)

    def set_selected_file(self, path):
        self.selected_file = path
        size_mb = os.path.getsize(path) / (1024 * 1024)
        self.info_label.configure(text=f"Archivo ZIP listo: {os.path.basename(path)} ({size_mb:.2f} MB)")
        self.convert_button.configure(state="normal")
        self.add_log(f"ZIP cargado: {path}")

    def update_progress(self, value):
        self.progress_bar.set(value)
        self.update_idletasks()

    def add_log(self, message):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"> {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def start_conversion(self):
        if not self.selected_file:
            return

        self.convert_button.configure(state="disabled")
        self.select_button.configure(state="disabled")
        self.progress_bar.set(0)
        
        # Ejecutar en un hilo separado para no bloquear la UI
        thread = threading.Thread(target=self.run_extraction)
        thread.start()

    def run_extraction(self):
        try:
            self.extractor.extract(self.selected_file)
            messagebox.showinfo("Completado", "¡Extracción finalizada con éxito!\n\nEl archivo config.json ha sido generado en la misma carpeta del backup.")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error: {str(e)}")
        finally:
            self.convert_button.configure(state="normal")
            self.select_button.configure(state="normal")


if __name__ == "__main__":
    app = App()
    app.mainloop()
