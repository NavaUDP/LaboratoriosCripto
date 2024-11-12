from alg import aes_256, des, des3
from decipher import aes_decipher, des3_decipher, des_decipher

while True:
    # Comenzamos con DES
    print("DES")
    key = input("Ingrese la llave a utilizar con DES: ")
    while True:
        iv = input("Ingrese el vector de inicializacion a utilizar con DES: ")
        if len(iv) == 8:
            break
        else:
            print("El vector de inicializacion debe ser de 8 caracteres. Intente de nuevo.")

    texto = input("Ingrese el mensaje a cifrar: ")
    key_bytes, iv_bytes, msg = des(key, iv, texto)
    print(" ")
    print("------------------------------------------|Se procede a decifrar el mensaje|------------------------------------------")
    print(" ")
    des_decipher(key_bytes, iv_bytes, msg)

    print(" ")
    print("------------------------------------------|SIGUIENTE METODO|------------------------------------------")
    print(" ")

    # Ahora con AES
    print("AES")
    key = input("Ingrese la llave a utilizar con AES: ")
    while True:
        iv = input("Ingrese el vector de inicializacion a utilizar con AES: ")
        if len(iv) == 16:
            break
        else:
            print("El vector de inicializacion debe ser de 16 caracteres. Intente de nuevo.")

    texto = input("Ingrese el mensaje a cifrar: ")
    key_bytes, iv_bytes, msg = aes_256(key, iv, texto)
    print(" ")
    print("------------------------------------------|Se procede a decifrar el mensaje|------------------------------------------")
    print(" ")
    aes_decipher(key_bytes, iv_bytes, msg)

    print(" ")
    print("------------------------------------------|SIGUIENTE METODO|------------------------------------------")
    print(" ")

    # Por ultimo con 3DES
    print("3DES")
    key = input("Ingrese la llave a utilizar con 3DES: ")
    while True:
        iv = input("Ingrese el vector de inicializacion a utilizar con 3DES: ")
        if len(iv) == 8:
            break
        else:
            print("El vector de inicializacion debe ser de 8 caracteres. Intente de nuevo.")

    texto = input("Ingrese el mensaje a cifrar: ")
    key_bytes, iv_bytes, msg = des3(key, iv, texto)
    print(" ")
    print("------------------------------------------|Se procede a decifrar el mensaje|------------------------------------------")
    print(" ")
    des3_decipher(key_bytes, iv_bytes, msg)

    break