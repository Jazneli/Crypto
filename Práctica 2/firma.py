from typing import KeysView
from Crypto import PublicKey
import Crypto
from Crypto.PublicKey import RSA
from tkinter.filedialog import askopenfilename
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

def fileselectE():
    while True:
        filename = askopenfilename()
        if (filename.find(".txt")!=-1):
            print("Correct File")
            f=open(filename,"r")
            mensaje=f.read()
            f.close
            return mensaje
        else:
            print("Choose a file correct (.txt)")

def fileselect():
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

def signature():
    print("Elige el mensaje a validar")
    msg=str(fileselectE())
    hash = SHA256.new(msg.encode())
    print("Ingresa la llave privada correspondiente")
    #
    keyPair = RSA.importKey(fileselect())
    #
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    f = open("signature.txt","wb")
    f.write(signature)
    f.close
    signature_hex = signature.hex()
    divider_message_sign = "*__*"
    f = open("message_signature.txt","w")
    f.write(msg+divider_message_sign+signature_hex)
    f.close

def validate():
    print("Elige el mensaje con la firma a validar")
    msg_sign = str(fileselectE())
    index_divider = msg_sign.find('*__*')
    msg=msg_sign[0:index_divider].encode()
    hash = SHA256.new(msg)
    print("Ingresa la llave pública correspondiente")
    #
    pubKey = RSA.importKey(fileselect())
    #
    verifier = PKCS115_SigScheme(pubKey)
    try:
        signature = msg_sign[index_divider+4:]
        verifier.verify(hash, bytearray.fromhex(signature))
        print("Signature is valid.")
    except:
        print("Signature is invalid.") 

def main():

    print("*****MENÚ*****")
    print("1.-Hacer Firma Digital")
    print("2.-Validar")
    print("0.-Salir")

    opcion = int(input("Ingresa la opcion -> "))

    if(opcion == 1):
        signature()

    elif(opcion == 2):
        validate()


if __name__ == "__main__":
    main()