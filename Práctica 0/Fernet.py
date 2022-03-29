#Se importa el módulo FERNET de la biblioteca Cryptography
import base64
from fileinput import filename
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter.filedialog import askopenfilename

# ----------------- ELEGIR ARCHIVO PARA LEER LA LLAVE-------------------------
def fileselectK():
    while True:
        filenameK = askopenfilename()
        if (filenameK.find(".txt")!=-1):
            print("ARCHIVO CORRECTO")
            f=open(filenameK,"r")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("SELECCIONA UN ARCHIVO CORRECTO (.txt)")

# ----------------- ELEGIR ARCHIVO PARA CIFRAR-------------------------
def fileselectE():
    while True:
        filename = askopenfilename()
        if (filename.find(".txt")!=-1):
            print("ARCHIVO CORRECTO")
            f=open(filename,"r")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("SELECCIONA UN ARCHIVO CORRECTO (.txt)")

# ----------------- ELEGIR ARCHIVO PARA DESCIFRAR-------------------------
def fileselectD():
    while True:
        filename = askopenfilename()
        if (filename.find(".txt")!=-1):
            print("ARCHIVO CORRECTO")
            f=open(filename,"r")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("SELECCIONA UN ARCHIVO CORRECTO (.txt)")

# ----------------- CIFRAR -------------------------
def encrypt():
    try:
        message=str(fileselectE())
        # ----------------- LLAVE -------------------------
        passw = input("Ingresa la llave: ")
        password = str(passw)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )

        #Generamos la llave
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        #Se asigna el valor que se genero para la llave
        llave = Fernet(key)
        cifrar = llave.encrypt(message.encode())

        f = open("encrypt.txt","w")
        f.write(cifrar.decode())
        f.close
        print("CIFRADO CORRECTO")

        k = open("key.txt","w")
        k.write(key.decode())
        k.close
        print("Llave generada con exito")
    except:
        print("ERROR cifrar archivo")

# ----------------- DESCIFRAR -------------------------
def decrypt():
    try:
        cipher=str(fileselectD())
        key = str(fileselectK())
        llave = Fernet(key)
        decrypted =  llave.decrypt(cipher.encode())
        f = open("decrypt.txt","w")
        f.write(decrypted.decode())
        f.close
        print("DESCIFRADO CORRECTAMENTE")
    except:
        print("ERROR descifrar")


def main():
    while True:
        try:
            print("\n FERNET Cipher")
            print("1.- Encrypt")
            print("2.- Decrypt")
            print("0.- Exit")
            opcion = int(input("Enter your option -> "))
            if opcion==1:
                encrypt()
            elif opcion==2:
                decrypt()
            elif opcion==0:
                break
            else:
                print()
        except:
            print("ERROR DEL MAIN")


if __name__=='__main__':
    main()