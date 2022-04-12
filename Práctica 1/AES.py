from Crypto.Cipher import AES
import hashlib
from tkinter.filedialog import askopenfilename

def fileselect():
    while True:
        filename = askopenfilename()
        if (filename.find(".bmp")!=-1):
            print("Correct File")
            f=open(filename,"rb")
            mensaje=f.read()
            mensajebyte = bytearray(mensaje)
            f.close
            return mensajebyte
        else:
            print("Choose a file correct")

def GiveRGBAndPixels(ArrayImage):
    return ArrayImage[0:54], ArrayImage[54:len(ArrayImage)]

def pad_message(file):
    while len(file)%16 != 0:
        file = file + b"0"
    return file

def encrypt_ECB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_ECB
    cipher = AES.new(key,mode)
    orig_file = fileselect()
    cabecera, image = GiveRGBAndPixels(orig_file)
    padded_file = pad_message(image)
    encrypted_file = cipher.encrypt(padded_file)
    with open('image_eECB.bmp','wb') as e:
        e.write(cabecera+encrypted_file)

def decrypt_ECB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_ECB
    cipher = AES.new(key, mode)
    encrypted_file = fileselect()
    cabecera, image = GiveRGBAndPixels(encrypted_file)
    decrypted_file = cipher.decrypt(image)
    with open('image_eECB_dECB.bmp','wb') as df:
        df.write(cabecera+decrypted_file)

def encrypt_CBC():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CBC
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key,mode,IV)
    orig_file = fileselect()
    cabecera, image = GiveRGBAndPixels(orig_file)
    padded_file = pad_message(image)
    encrypted_file = cipher.encrypt(padded_file)
    with open('image_eCBC.bmp','wb') as e:
        e.write(cabecera+encrypted_file)

def decrypt_CBC():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CBC
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key, mode,IV)
    encrypted_file = fileselect()
    cabecera, image = GiveRGBAndPixels(encrypted_file)
    decrypted_file = cipher.decrypt(image)
    with open('image_eCBC_dCBC.bmp','wb') as df:
        df.write(cabecera+decrypted_file)

def encrypt_CFB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CFB
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key,mode,IV)
    orig_file = fileselect()
    cabecera, image = GiveRGBAndPixels(orig_file)
    padded_file = pad_message(image)
    encrypted_file = cipher.encrypt(padded_file)
    with open('image_eCFB.bmp','wb') as e:
        e.write(cabecera+encrypted_file)

def decrypt_CFB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CFB
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key, mode,IV)
    encrypted_file = fileselect()
    cabecera, image = GiveRGBAndPixels(encrypted_file)
    decrypted_file = cipher.decrypt(image)
    with open('image_eCFB_dCFB.bmp','wb') as df:
        df.write(cabecera+decrypted_file)

def encrypt_OFB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_OFB
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key,mode,IV)
    orig_file = fileselect()
    cabecera, image = GiveRGBAndPixels(orig_file)
    padded_file = pad_message(image)
    encrypted_file = cipher.encrypt(padded_file)
    with open('image_eOFB.bmp','wb') as e:
        e.write(cabecera+encrypted_file)

def decrypt_OFB():
    while(True):
        password = input("Ingresa el pasword (16 caracteres) -> ").encode()
        if(len(password) == 16):
            break
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_OFB
    while(True):
        IV = input("Ingresa el vector de inicialización (16 caracteres) -> ").encode()
        if(len(IV) == 16):
            break
    cipher = AES.new(key, mode,IV)
    encrypted_file = fileselect()
    cabecera, image = GiveRGBAndPixels(encrypted_file)
    decrypted_file = cipher.decrypt(image)
    with open('image_eOFB_dOFB.bmp','wb') as df:
        df.write(cabecera+decrypted_file)

def main():
    print("*****MENÚ*****")
    print("1.-ECB Encrypt")
    print("2.-ECB Decrypt")
    print("3.-CBC Encrypt")
    print("4.-CBC Decrypt")
    print("5.-CFB Encrypt")
    print("6.-CFB Decrypt")
    print("7.-OFB Encrypt")
    print("8.-OFB Decrypt")
    print("0.-Salir")
    opcion = int(input("Ingresa la opcion -> "))
    if(opcion == 1):
        encrypt_ECB()
    elif(opcion == 2):
        decrypt_ECB()

    elif(opcion == 3):  
        encrypt_CBC()   
    elif(opcion == 4):  
        decrypt_CBC()   

    elif(opcion == 5):
        encrypt_CFB()
    elif(opcion == 6):
        decrypt_CFB()

    elif(opcion == 7):
        encrypt_OFB()
    elif(opcion == 8):
        decrypt_OFB()


if __name__ == "__main__":
    main()