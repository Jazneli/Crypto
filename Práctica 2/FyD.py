from pathlib import Path
from base64 import decode
from fileinput import filename
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter.filedialog import askopenfilename
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


def fileselect():
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

def signature():
    print("Elige el mensaje a validar")
    msg=str(fileselect())
    hash = SHA256.new(msg.encode())
    print("Ingresa la llave privada correspondiente")
    keyPair = RSA.importKey(fileselectK())
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
    msg_sign = str(fileselect())
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
    print("2. Firmar / Verificar")
    op = int(input("Ingresa la opcion: "))
    if(op == 1):
        llaves()

    elif(op == 2):
        print("*****MENÚ SIGNATURE*****")
        print("1. Firmar")
        print("2. Verificar")
        op3 = int(input("Ingresa la opcion: "))
        if(op3 == 1):
            signature()
        elif(op3 == 2):
            validate()

if __name__ == "__main__":
    main()