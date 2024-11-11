import base64
import secrets
import string
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from decipher import des_decipher, aes_decipher, des3_decipher

def des(key, iv, msg):
    #Se pasa toda la informacion que se le entrega a la funcion a bytes
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    msg_bytes = msg.encode('utf-8')

    #Modificamos la clave para que cumpla con el largo necesario
    if len(key_bytes) == 8:
        print("La llave en bytes es: ", key_bytes)
    elif len(key_bytes) < 8:
        extra_bytes = get_random_bytes(8 - len(key_bytes))
        key_bytes += extra_bytes
        print("La llave modificada en bytes es: ", key_bytes)
    elif len(key_bytes) > 8:
        key_bytes = key_bytes[:8]
        print("La llave modificada en bytes es: ", key_bytes)

    #Ahora analizamos el vector de inicializacion
    if len(iv_bytes) == 8:
        print("El vector de inicializacion es: ", iv_bytes)
    elif len(iv_bytes) < 8:
        extra_bytes = get_random_bytes(8 - len(iv_bytes))
        iv_bytes += extra_bytes
        print("vector de inicializacion modificado: ", iv_bytes)
    elif len(iv_bytes) > 8:
        iv_bytes = iv_bytes[:8]
        print("El vector de inicializacion es: ", iv_bytes)

    #Ahora analizamos el mensaje
    if len(msg) % 8 != 0:
        #se le aplica un padding
        msg_bytes = pad(msg_bytes, DES.block_size)
        msg_base64 = base64.b64encode(msg_bytes).decode('utf-8')
    else:
        msg_base64 = base64.b64encode(msg_bytes).decode('utf-8')

    #Se crea el objeto para el cifrado
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)

    ciphertext = cipher.encrypt(msg_bytes)
    print("El mensaje ecriptado es: ", ciphertext)

    # Convertir el texto cifrado a base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    print("El mensaje ecriptado en base64 es: ", ciphertext_base64)

    return key_bytes, iv_bytes, ciphertext

def aes_256(key, iv, msg):
    # Se pasa toda la información que se le entrega a la función a bytes
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    msg_bytes = msg.encode('utf-8')

    # Modificamos la clave para que cumpla con el largo necesario
    if len(key_bytes) == 16:
        print("La llave en bytes es: ", key_bytes)
    elif len(key_bytes) < 16:
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes
        print("La llave modificada en bytes es: ", key_bytes)
    elif len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
        print("La llave modificada en bytes es: ", key_bytes)

    # Ahora analizamos el vector de inicialización
    if len(iv_bytes) == 16:
        print("El vector de inicializacion es: ", iv_bytes)
    elif len(iv_bytes) < 16:
        extra_bytes = get_random_bytes(16 - len(iv_bytes))
        iv_bytes += extra_bytes
        print("vector de inicializacion modificado: ", iv_bytes)
    elif len(iv_bytes) > 16:
        iv_bytes = iv_bytes[:16]
        print("El vector de inicializacion es: ", iv_bytes)

    # Ahora analizamos el mensaje
    if len(msg_bytes) % 16 != 0:
        # se le aplica un padding
        msg_bytes = pad(msg_bytes, AES.block_size)
        print("Mensaje antes de encriptar (con padding): ", msg_bytes)
    else:
        print("Mensaje antes de encriptar: ", msg_bytes)

    # Se crea el objeto para el cifrado
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    ciphertext = cipher.encrypt(msg_bytes)
    print("El mensaje encriptado es: ", ciphertext)

    # Convertir el texto cifrado a base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    print("El mensaje encriptado en base64 es: ", ciphertext_base64)

    return key_bytes, iv_bytes, ciphertext


def des3(key, iv, msg):
    # Se pasa toda la información que se le entrega a la función a bytes
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    msg_bytes = msg.encode('utf-8')

    # Modificamos la clave para que cumpla con el largo necesario
    if len(key_bytes) == 16 or len(key_bytes) == 24:
        print("La llave en bytes es: ", key_bytes)
    elif len(key_bytes) < 16:
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes
        print("La llave modificada en bytes es: ", key_bytes)
    elif len(key_bytes) > 24:
        key_bytes = key_bytes[:24]
        print("La llave modificada en bytes es: ", key_bytes)

    # Ahora analizamos el vector de inicialización
    if len(iv_bytes) == 8:
        print("El vector de inicializacion es: ", iv_bytes)
    elif len(iv_bytes) < 8:
        extra_bytes = get_random_bytes(8 - len(iv_bytes))
        iv_bytes += extra_bytes
        print("vector de inicializacion modificado: ", iv_bytes)
    elif len(iv_bytes) > 8:
        iv_bytes = iv_bytes[:8]
        print("El vector de inicializacion es: ", iv_bytes)

    # Ahora analizamos el mensaje
    if len(msg_bytes) % 8 != 0:
        # se le aplica un padding
        msg_bytes = pad(msg_bytes, DES3.block_size)
        print("Mensaje antes de encriptar (con padding): ", msg_bytes)
    else:
        print("Mensaje antes de encriptar: ", msg_bytes)

    # Se crea el objeto para el cifrado
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv_bytes)

    ciphertext = cipher.encrypt(msg_bytes)
    print("El mensaje encriptado es: ", ciphertext)

    # Convertir el texto cifrado a base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    print("El mensaje encriptado en base64 es: ", ciphertext_base64)

    return key_bytes, iv_bytes, ciphertext

#Inputs que se utilizaron en el testeo del codigo

#key_bytes, iv_bytes, msg = des("diego", "maradoniiiano", "texto encriptado con des")
#des_decipher(key_bytes, iv_bytes, msg)
#
#key2, iv2, msg2 = aes_256("diego", "maradoniiiano", "texto encriptado con aes-256")
#aes_decipher(key2, iv2, msg2)
#
#key3, iv3, msg3 = des3("diego", "maradoniiiano", "texto encriptado con des3")
#des3_decipher(key3, iv3, msg3)