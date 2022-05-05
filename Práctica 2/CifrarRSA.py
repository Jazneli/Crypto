from inspect import signature
import os
import base64
from base64 import decode
from fileinput import filename
from tkinter.filedialog import askopenfilename
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from typing import KeysView
from Crypto import PublicKey
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import binascii

def fileselect():
    while True:
        filename = askopenfilename()
        if (filename.find(".txt")!=-1):
            print("Correct File")
            f=open(filename,"rb")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("Choose a file correct (.txt)")

def fileselectK():
    while True:
        filename = askopenfilename()
        if (filename.find(".pem")!=-1):
            print("Correct File")
            f=open(filename,"rb")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("Choose a file correct (.txt)")

def llaves():
    keys = RSA.generate(1024)
    print("\n *****GENERAR LLAVES PARA RSA*****")
    nombre = input("Ingresa el nombre del propietario de las llaves: ")
    nombreKey = f'{nombre}_PrivateKey.pem'
    with open(nombreKey,'wb') as privKey:
        privKey.write(keys.exportKey("PEM"))
    nombreKeyPu = f'{nombre}_PublicKey.pem'
    with open(nombreKeyPu, 'wb') as publKey:
        publKey.write(keys.publickey().exportKey("PEM"))
    print("Se generaron exitosamente las llaves")

def cifrar():
    print("\n *****CIFRAR CON RSA*****")
    print("Selecciona el mensaje a cifrar: ")
    archivo = os.path.basename(fileselect())
    message = str(archivo)
    print("Selecciona llave publica del receptor: ")
    keyReceptor = RSA.importKey(fileselectK())
    cifrar = PKCS1_OAEP.new(keyReceptor)
    mcifrar = cifrar.encrypt(message.encode())
    nombreArchivoC = f'{archivo}_C.txt'
    with open(nombreArchivoC,'wb') as e:
        e.write(mcifrar)

def descifrar():
    print("\n *****DESCIFRAR CON RSA*****")
    print("Selecciona el mensaje a descifrar: ")
    archivo = os.path.basename(fileselect())
    message = str(archivo)
    decoded_data = base64.b64decode(message)
    print("Selecciona llave privada del receptor: ")
    keyReceptorPriv = RSA.importKey(fileselectK())
    descifrar = PKCS1_OAEP.new(keyReceptorPriv)
    messageD = descifrar.decrypt(decoded_data)
    print(messageD)
    '''nombreArchivoD = f'{archivo}_D.txt'
    with open(nombreArchivoD,'wb') as e:
        e.write(messageD)'''

def firmar():
    print("Elige el mensaje a firmar")
    archivo = os.path.basename(fileselect())
    msg=str(archivo).encode()
    hash = SHA256.new(msg)
    print("Ingresa la llave privada correspondiente")
    keyPair = RSA.importKey(fileselectK())
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    nombreArchivoS = f'{archivo}_signature.txt'
    with open(nombreArchivoS,'wb') as s:
        s.write(signature)
    signature_hex = signature.hex()
    divider_message_sign = "*__*"
    msg2 = str(archivo)
    f = open("message_signature.txt","w")
    f.write(msg2+divider_message_sign+signature_hex)
    f.close

def verificar():
    print("Elige el mensaje con la firma a validar")
    archivo = os.path.basename(fileselect())
    msg_sign=str(archivo)
    index_divider = msg_sign.find('*__*')
    msg=msg_sign[0:index_divider].encode()
    hash = SHA256.new(msg)
    print("Ingresa la llave pública correspondiente")
    pubKey = RSA.importKey(fileselectK())
    verifier = PKCS115_SigScheme(pubKey)
    try:
        signature = msg_sign[index_divider+4:]
        verifier.verify(hash, bytearray.fromhex(signature))
        print("Signature is valid.")
    except:
        print("Signature is invalid.") 

def main():
    print("*****MENÚ*****")
    print("1. Generar Llaves para RSA")
    print("2. Cifrar / Descifrar")
    print("3. Firmar / Verificar")
    op = int(input("Ingresa la opcion: "))
    if(op == 1):
        llaves()

    elif(op == 2):
        print("*****MENÚ RSA*****")
        print("1. Cifrar")
        print("2. Descifrar")
        op2 = int(input("Ingresa la opcion: "))
        if(op2 == 1):
            cifrar()
        elif(op2 == 2):
            descifrar()

    elif(op == 3):
        print("*****MENÚ SIGNATURE*****")
        print("1. Firmar")
        print("2. Verificar")
        op3 = int(input("Ingresa la opcion: "))
        if(op3 == 1):
            firmar()
        elif(op3 == 2):
            verificar()

if __name__ == "__main__":
    main()