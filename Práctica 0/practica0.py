#Se importa el módulo FERNET de la biblioteca Cryptography
import base64
import os
from turtle import width
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
import tkinter as tk
from tkinter import HORIZONTAL, NONE, filedialog , ttk, Scrollbar, INSERT, DISABLED, END, Text, VERTICAL, NS
import tkinter.font as tkFont
from tkinter.simpledialog import askstring
from tkinter.messagebox import showinfo

def leerTxt(archivo):
    archivo = open(archivo)
    txt = archivo.read()
    archivo.close()    
    desplegarTexto(txt)

def desplegarTexto(texto):
    txtBox.delete('1.0', END)
    txtBox.insert(INSERT, texto)
    txtBox.config(state=DISABLED)

def desplegarRuta(texto):
    txtRuta.delete('1.0', END)
    txtRuta.insert(INSERT, texto)
    txtRuta.config(state=DISABLED)

def seleccionarArchivo(): 
    filename = filedialog.askopenfilename(initialdir = "/", 
            title = "Selecciona un archivo de texto", 
            filetypes = (("Txt files", 
            "*.txt*"), 
            ("all files", 
            "*.*"))) 
    desplegarRuta(filename)
    leerTxt(filename)

def seleccionarLlave(): 
    filename = filedialog.askopenfilename(initialdir = "/", 
            title = "Selecciona un archivo de texto", 
            filetypes = (("Txt files", 
            "*.txt*"), 
            ("all files", 
            "*.*"))) 
    return filename

# Cifrar
def cifrar():
    try:
        rutaArchivo = txtRuta.get('1.0', END)
        print(rutaArchivo)
        txt = txtBox.get('1.0', END)
        # ----------------- LLAVE -------------------------    
        passw = askstring('Llave', 'Ingresa la llave: ')
        password = str(passw)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        # Generamos la llave
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        nombreArchivo  = Path(rutaArchivo).stem
        # Se asigna el valor que se genero para la llave
        llave = Fernet(key)
        cifrar = llave.encrypt(txt.encode())
        nombreCifrado = nombreArchivo+"_C.txt" 
        f = open(nombreCifrado,"w")
        texto = cifrar.decode()
        f.write(texto)
        f.close
        k = open("key.txt","w")
        k.write(key.decode())
        k.close
        txtBox2.delete('1.0', END)
        txtBox2.insert(INSERT, texto)
        txtBox2.config(state=DISABLED)
        showinfo(message="Los archivos han sido generados.",title="Cifrado exitoso.")
    except:
        showinfo(message="Error al cifrar",title="Error")

# Descifrar
def descifrar():
    try:
        txt = txtBox.get('1.0', END)
        nombre = seleccionarLlave()
        archivoKey = open(nombre)
        key = archivoKey.read()
        llave = Fernet(key)
        decrypted =  llave.decrypt(txt.encode())
        rutaArchivo = txtRuta.get('1.0', END)
        nombreArchivo  = Path(rutaArchivo).stem
        nombreDescifrado = nombreArchivo[:-2]
        nombreDescifrado = nombreDescifrado+"_D.txt" 
        f = open(nombreDescifrado,"w")
        texto = decrypted.decode()
        f.write(texto)
        f.close
        txtBox2.delete('1.0', END)
        txtBox2.insert(INSERT, texto)
        txtBox2.config(state=DISABLED)
        showinfo(message="El archivo ha sido generado.",title="Descifrado exitoso.")
    except:
        showinfo(message="Error al descifrar",title="Error")

# Ventana principal
root = tk.Tk()
root.geometry("900x610")
root.title('Práctica 0')
root.configure(bg='black')
#root.iconbitmap('./key.ico')

# Configurar Grid
root.columnconfigure(0, weight=10) 
root.columnconfigure(1, weight=3) 
root.columnconfigure(2, weight=10) 
root.columnconfigure(3, weight=3) 
#root.columnconfigure(4, weight=3) 
#root.columnconfigure(5, weight=3) 

# Tipos de letra
bah8 = tkFont.Font(family='Bahnschrift', size=8)
bah10 = tkFont.Font(family='Bahnschrift', size=10)
bah11 = tkFont.Font(family='Bahnschrift', size=11)
bah12 = tkFont.Font(family='Bahnschrift', size=12)
bah16 = tkFont.Font(family='Bahnschrift', size=16)

# Texto Titulo
txtTitulo = ttk.Label(root, 
    text="F E R N E T (CIFRADO SIMÉTRICO)",
    font=bah16)
txtTitulo.configure(foreground="cyan", background="black")
txtTitulo.grid(column=0, row=0, sticky=tk.W, padx=2, pady=2)

# Texto Seleccion de Archivo
txtEntrada = ttk.Label(root, 
    text="Ruta del Archivo:",
    font=bah12)
txtEntrada.configure(foreground="white", background="black")
txtEntrada.grid(column=1, row=1, sticky=tk.W, padx=2, pady=2)

# Boton Seleccionar Archivo
style = ttk.Style()
style.configure("BW.TLabel", background="#143A67", 
    foreground="cyan", font=bah11)
btnArchivo = ttk.Button(root, text="SELECCIONAR ARCHIVO", 
    command = seleccionarArchivo, style="BW.TLabel")
btnArchivo.grid(column=0, row=1, sticky=tk.NW, padx=5, pady=5)


# Desplegar ruta del archivo
sb3 = Scrollbar(root, orient=HORIZONTAL)
txtRuta = Text(root, height=2, width=45, font=bah8, wrap=NONE, xscrollcommand=sb3.set)
txtRuta.configure(foreground="white")
txtRuta.grid(row=1, column=2)
txtRuta.config(bg='#353535')
sb3.grid(row=2, column=2, sticky=NS)
sb3.config(command=txtRuta.xview)

# Texto Entrada
txtEntrada = ttk.Label(root, 
    text="Texto de entrada:",
    font=("Bahnschrift", 10))
txtEntrada.configure(foreground="white", background="black", font=bah12)
txtEntrada.grid(column=0, row=3, sticky=tk.W, padx=2, pady=2)

# Texto Entrada Desplegado
txtBox = Text(root, height=35, width=45, font=bah8)
txtBox.configure(foreground="white")
txtBox.grid(row=4, column=0)
txtBox.config(bg='#353535')
sb = Scrollbar(root, orient=VERTICAL)
sb.grid(row=4, column=1, sticky=NS)
txtBox.config(yscrollcommand=sb.set)
sb.config(command=txtBox.yview)

# Texto Salida
txtSalida = ttk.Label(root, text="Salida:")
txtSalida.configure(foreground="white", background="black", font=bah12)
txtSalida.grid(column=2, row=3, sticky=tk.W, padx=5, pady=5)

# Texto Salida Desplegado
txtBox2 = Text(root, height=35, width=45, font=bah8)
txtBox2.configure(foreground="white")
txtBox2.grid(row=4, column=2)
txtBox2.config(bg='#353535')
sb2 = Scrollbar(root, orient=VERTICAL)
sb2.grid(row=4, column=3, sticky=NS)
txtBox2.config(yscrollcommand=sb2.set)
sb2.config(command=txtBox2.yview)

# Botones
btnCifrar = ttk.Button(root, text="CIFRAR TEXTO", command=cifrar, style="BW.TLabel")
btnCifrar.grid(column=0, row=5, sticky=tk.NW, padx=10, pady=10)

btnDescifrar = ttk.Button(root, text="DESCIFRAR TEXTO", command=descifrar, style="BW.TLabel")
btnDescifrar.grid(column=1, row=5, sticky=tk.NW, padx=10, pady=10)

root.mainloop()