from fileinput import filename
from tkinter.filedialog import askopenfilename
from Crypto import PublicKey
from Crypto.PublicKey import RSA

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

def main():
    llaves()

if __name__ == "__main__":
    main()