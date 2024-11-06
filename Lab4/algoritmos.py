import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def alg_des():
    #Para que el algoritmo funcione, todas las variables deben tener 8 caracteres
    key = input("Ingrese la clave a utilizar: ")
    if len(key) == 8:
        key_bytes = key.encode('utf-8')
    elif len(key) < 8:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(8 - len(key_bytes))
        key_bytes += extra_bytes

        print("clave modificada: ", key_bytes)

    elif len(key) > 8:
        key_bytes = key[:8].encode('utf-8')

        print("clave modificada: ", key_bytes)

    vector = input("Ingrese el vector de inicializacion (IV): ")
    if len(vector) == 8:
        vector_bytes = vector.encode('utf-8')
    elif len(vector) < 8:
        #Generar el resto de bytes para el vector
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(8 - len(vector_bytes))
        vector_bytes += extra_bytes

        print("vector de inicializacion modificado: ", vector_bytes)

    elif len(vector) > 8:
        vector_bytes = vector[:8].encode('utf-8')  

        print("vector de inicializacion modificado: ", vector_bytes)  
    
    text = input("Ingrese el texto a cifrar, debe tener como minimo 8 caracteres: ")
    text_bytes = text.encode('utf-8')

    #objeto para el cifrado
    cipher = DES.new(key_bytes, DES.MODE_CBC, vector_bytes)

    #cifrado
    ciphertext = cipher.encrypt(text_bytes)
    print("Texto cifrado: ", ciphertext)

def alg_aes_256():
    key = input("Ingrese la clave a utilizar: ")
    if len(key) == 16:
        key_bytes = key.encode('utf-8')
    elif len(key) < 16:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes

        print("clave modificada: ", key_bytes)

    elif len(key) > 16:
        key_bytes = key[:16].encode('utf-8')

        print("clave modificada: ", key_bytes)   

    vector = input("Ingrese el vector de inicializacion (IV): ")
    if len(vector) == 16:
        vector_bytes = vector.encode('utf-8')
    elif len(vector) < 16:
        #Generar el resto de bytes para el vector
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(vector_bytes))
        vector_bytes += extra_bytes

        print("vector de inicializacion modificado: ", vector_bytes)

    elif len(vector) > 16:
        vector_bytes = vector[:16].encode('utf-8')  

        print("vector de inicializacion modificado: ", vector_bytes)  
    
    #En AES el mensaje tiene que ser multiplo de 16
    text = input("Ingrese el texto a cifrar: ")
    text_bytes = text.encode('utf-8')
    if len(text) % 16 != 0:
        padded_text = pad(text_bytes,AES.block_size)

    #cifrado
    cipher = AES.new(key_bytes, AES.MODE_CBC, vector_bytes)

    ciphertext = cipher.encrypt(padded_text)
    ciphertext_base64 = base64.b64encode(ciphertext)
    print("Texto antes del cifrado: ", text_bytes)
    print("Texto cifrado con AES: ", ciphertext_base64)
