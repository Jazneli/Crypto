from Crypto.Cipher import AES
import hashlib
from tkinter import NS, NW, VERTICAL, Button, Canvas, Entry, PhotoImage, Scrollbar, StringVar, Text, Tk, ttk, messagebox, filedialog, INSERT, DISABLED, END, NORMAL, Frame, RAISED, Label, RIGHT
from tkinter.simpledialog import askstring
import tkinter.font as tkFont
from PIL import Image, ImageTk
from pathlib import Path

class P1(Frame):
    def __init__(self, master, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.parent = master
        self.grid()
        self.createWidgets()
    
    def GiveRGBAndPixels(self, ArrayImage):
        return ArrayImage[0:54], ArrayImage[54:len(ArrayImage)]

    def imageToBytes(self, filename):
        fn = filename[6:]
        f=open(fn,"rb")
        mensaje=f.read()
        mensajebyte = bytearray(mensaje)
        f.close
        return mensajebyte

    def pad_message(self, file):
        while len(file)%16 != 0:
            file = file + b"0"
        return file

    def encrypt_ECB(self, password, ruta, mensajeBytes):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_ECB
        cipher = AES.new(key,mode)
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        padded_file = self.pad_message(image)
        encrypted_file = cipher.encrypt(padded_file)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_eECB.bmp'
        with open(nombreImg,'wb') as e:
            e.write(cabecera+encrypted_file)
        self.desplegarImg(nombreImg)

    def encrypt_CBC(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_CBC
        cipher = AES.new(key,mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        padded_file = self.pad_message(image)
        encrypted_file = cipher.encrypt(padded_file)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_eCBC.bmp'
        with open(nombreImg,'wb') as e:
            e.write(cabecera+encrypted_file)
        self.desplegarImg(nombreImg)

    def encrypt_CFB(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_CFB
        cipher = AES.new(key,mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        padded_file = self.pad_message(image)
        encrypted_file = cipher.encrypt(padded_file)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_eCFB.bmp'
        with open(nombreImg,'wb') as e:
            e.write(cabecera+encrypted_file)
        self.desplegarImg(nombreImg)

    def encrypt_OFB(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_OFB
        cipher = AES.new(key,mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        padded_file = self.pad_message(image)
        encrypted_file = cipher.encrypt(padded_file)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_eOFB.bmp'
        with open(nombreImg,'wb') as e:
            e.write(cabecera+encrypted_file)
        self.desplegarImg(nombreImg)    

    def decrypt_ECB(self, password, ruta, mensajeBytes):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_ECB
        cipher = AES.new(key, mode)
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        decrypted_file = cipher.decrypt(image)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_dECB.bmp'
        with open(nombreImg,'wb') as df:
            df.write(cabecera+decrypted_file)
        self.desplegarImg(nombreImg) 

    def decrypt_CBC(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_CBC
        cipher = AES.new(key, mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        decrypted_file = cipher.decrypt(image)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_dCBC.bmp'
        with open(nombreImg,'wb') as df:
            df.write(cabecera+decrypted_file)
        self.desplegarImg(nombreImg)

    def decrypt_CFB(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_CFB
        cipher = AES.new(key, mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        decrypted_file = cipher.decrypt(image)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_dCFB.bmp'
        with open(nombreImg,'wb') as df:
            df.write(cabecera+decrypted_file)
        self.desplegarImg(nombreImg)

    def decrypt_OFB(self, password, ruta, mensajeBytes, c0):
        key = hashlib.sha256(password.encode()).digest()
        mode = AES.MODE_OFB
        cipher = AES.new(key, mode,c0.encode())
        cabecera, image = self.GiveRGBAndPixels(mensajeBytes)
        decrypted_file = cipher.decrypt(image)
        nombreArchivo  = Path(ruta[6:]).stem
        nombreImg=f'{nombreArchivo}_dOFB.bmp'
        with open(nombreImg,'wb') as df:
            df.write(cabecera+decrypted_file)
        self.desplegarImg(nombreImg)

    def leerImg(self, archivo):
        self.image = Image.open(archivo)
        self.python_image = ImageTk.PhotoImage(self.image)
        ttk.Label(self, image=self.python_image).grid(row=7, column=0)

    def desplegarImg(self, archivo):
        self.image2 = Image.open(archivo)
        self.python_image2 = ImageTk.PhotoImage(self.image2)
        ttk.Label(self, image=self.python_image2).grid(row=7, column=1)
    
    def seleccionarArchivo(self):
        filename = filedialog.askopenfilename(initialdir = "/", 
            title = "Selecciona una imagen formato BMP", 
            filetypes = (("Bmp files", 
            "*.bmp*"), 
            ("all files", 
            "*.*")))
        if(filename != ""):
            self.leerImg(filename)
            self.ruta.set(f'Ruta: {filename}')

    
    def validar(self, text, tipo, modo):
        if(tipo == "Imagen"):
            if(text == "Ruta: "):
                messagebox.showinfo(
                    message="Selecciona una imagen",
                    title="Falta archivo"
                )
                return False # Error
            else:
                return True

        if(len(text) != 16):
            if(tipo == "Llave"):
                messagebox.showinfo(
                    message="Ingresa una llave de 16 bytes",
                    title="Llave inválida"
                )
            else:
                if(modo != "ECB"):
                    messagebox.showinfo(
                        message="Ingresa un vector de inicialización de 16 bytes",
                        title="C0 inválido"
                    )
                    return False # Error
                return True
        else:
            return True # Parametros validos
        
    def validarOperacion(self):
        key = self.llave.get()
        modoOperacion = self.modoOperacion.get()
        opcionCifrado = self.opcionCifrado.get()
        c0 = self.c0.get()
        ruta = self.ruta.get()
        
        if (self.validar(ruta, "Imagen", modoOperacion) & self.validar(key, "Llave", modoOperacion) & self.validar(c0, "C0", modoOperacion) ):
            messagebox.showinfo(
                message="Imagen generada correctamente",
                title="OK"
            )
            if(opcionCifrado == "Cifrar"):
                rt = self.imageToBytes(ruta)
                if(modoOperacion == "ECB"):
                    self.encrypt_ECB(key, ruta, rt)
                if(modoOperacion == "CBC"):
                    self.encrypt_CBC(key, ruta, rt, c0)
                if(modoOperacion == "CFB"):
                    self.encrypt_CFB(key, ruta, rt, c0)
                if(modoOperacion == "OFB"):
                    self.encrypt_OFB(key, ruta, rt, c0)
            else:
                rt = self.imageToBytes(ruta)
                if(modoOperacion == "ECB"):
                    self.decrypt_ECB(key, ruta, rt)
                if(modoOperacion == "CBC"):
                    self.decrypt_CBC(key, ruta, rt, c0)
                if(modoOperacion == "CFB"):
                    self.decrypt_CFB(key, ruta, rt, c0)
                if(modoOperacion == "OFB"):
                    self.decrypt_OFB(key, ruta, rt, c0)

    def createWidgets(self):
        self.titulo = Label(self, font=("Arial", 12), relief=RAISED, text="P R Á C T I C A   1   C I F R A D O R   P O R   B L O Q U E S   A  E  S",justify=RIGHT, bg='black', fg='white')
        self.titulo.grid(row=0, column=0, columnspan=2, sticky="nsew")

        # Opciones modos de operacion
        # Texto
        self.cifrado = Label(self, text = "Operación:",
                font = ("Arial", 12)).grid(column = 0,
                row = 1, padx = 10, pady = 5)
        
        self.modos = Label(self, text = "Selecciona el modo de operación:",
                font = ("Arial", 12)).grid(column = 1,
                row = 1, padx = 10, pady = 5)

        self.llaveTxt = Label(self, text = "Ingresa la llave K0 (16 bytes):",
                font = ("Arial", 12)).grid(column = 0,
                row = 4, padx = 25, pady = 5)
        
        self.VectorTxt = Label(self, text = "Ingresa el vector de inicialización C0 (16 bytes):",
                font = ("Arial", 12)).grid(column = 1,
                row = 4, padx = 25, pady = 5)
        
        # Combobox Cifrado o Descifrado
        self.opcionCifrado = ttk.Combobox(
            self,
            state="readonly",
            values=["Cifrar", "Descifrar"]
        )
        self.opcionCifrado.grid(column = 0,
                row = 2, padx = 10, pady = 10)
        self.opcionCifrado.current(0)

        # Combobox Modo de operacion
        self.modoOperacion = ttk.Combobox(
            self,
            state="readonly",
            values=["ECB", "CBC", "CFB", "OFB"]
        )
        self.modoOperacion.grid(column = 1,
                row = 2, padx = 10, pady = 10)
        self.modoOperacion.current(0)

        # Boton de Seleccion Archivo
        self.archivoImg = Button(self, font=("Arial", 12), bg='gray',
            fg='white', text="Seleccionar Archivo", 
            highlightbackground='cyan', 
            command=lambda: self.seleccionarArchivo())
        self.archivoImg.grid(row=3, column=0, sticky="nsew")

        # Desplegar Ruta archivo
        self.ruta=StringVar()
        self.ruta.set("Ruta: ")
        self.rutaImg = Label(self, textvariable=self.ruta,
                font = ("Arial", 10)).grid(column = 1,
                row = 3, padx = 25, pady = 5)

        # Llave
        self.llave = Entry(self, font=("Arial", 12), 
            bg='#353535', 
            fg='white', 
            borderwidth=1)
        self.llave.grid(row=5, column=0, sticky="nsew")

        # Vector de inicializacion
        self.c0 = Entry(self, font=("Arial", 12), 
            bg='#353535', 
            fg='white', 
            borderwidth=1)
        self.c0.grid(row=5, column=1, sticky="nsew")

        # Boton de Generar Imagen
        self.generarImagen = Button(self, font=("Arial", 12), bg='blue',
            fg='white', text="Generar Imagen", 
            highlightbackground='white',
            command=self.validarOperacion)
        self.generarImagen.grid(row=6, column=0, sticky="nsew", columnspan=2)

        # Imagen Desplegadas
        ttk.Label(self).grid(row=7, column=0)
        ttk.Label(self).grid(row=7, column=1)

Practica1 = Tk()
Practica1.title("Práctica 1 Cifrador por bloques AES")
# Configurar Grid
root = P1(Practica1).grid()   
Practica1.configure(bg='black')
Practica1.resizable(False, False)
Practica1.mainloop()