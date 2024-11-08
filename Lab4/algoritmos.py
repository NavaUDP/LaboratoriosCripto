import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def alg_des(key, vector, text):
    #Para que el algoritmo funcione, todas las variables deben tener 8 caracteres
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
    
    text_bytes = text.encode('utf-8')
    if len(text) % 8 != 0:
        padded_text = pad(text_bytes,DES.block_size)

    #objeto para el cifrado
    cipher = DES.new(key_bytes, DES.MODE_CBC, vector_bytes)

    #cifrado
    ciphertext = cipher.encrypt(padded_text)
    ciphertext_base64 = base64.b64encode(ciphertext)
    print("Texto antes del cifrado: ", text_bytes)
    print("Texto cifrado con DES: ", ciphertext_base64)

    return ciphertext

def alg_aes_256(key, vector, text):
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
    
    text_bytes = text.encode('utf-8')
    if len(text) % 16 != 0:
        padded_text = pad(text_bytes,AES.block_size)

    #cifrado
    cipher = AES.new(key_bytes, AES.MODE_CBC, vector_bytes)

    ciphertext = cipher.encrypt(padded_text)
    ciphertext_base64 = base64.b64encode(ciphertext)
    print("Texto antes del cifrado: ", text_bytes)
    print("Texto cifrado con AES: ", ciphertext_base64)

    return ciphertext_base64

def alg_3des(key, vector, text):
    #Para que el algoritmo funcione, todas las variables deben tener 8 caracteres
    if len(key) == 16 or len(key) == 24:
        key_bytes = key.encode('utf-8')

    elif len(key) < 16:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes
        print("clave modificada: ", key_bytes)

    elif len(key) > 16:
        key_bytes = key[:8].encode('utf-8')
        print("clave modificada: ", key_bytes)

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

    text_bytes = text.encode('utf-8')
    if len(text) % 8 != 0:
        padded_text = pad(text_bytes,DES3.block_size)

    #objeto para el cifrado
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, vector_bytes)

    #cifrado
    ciphertext = cipher.encrypt(padded_text)
    ciphertext_base64 = base64.b64encode(ciphertext)
    print("Texto antes del cifrado: ", text_bytes)
    print("Texto cifrado con 3DES: ", ciphertext_base64)

    return ciphertext

def alg_des_decipher(key, vector, ciphertext):
    #Suponemos que la llave siempre va a ser correcta, al igual que el vector, por lo que solo invocamos al algoritmo
    #de igual manera hay que pasar el vector y la key a bytes
    if len(key) == 8:
        key_bytes = key.encode('utf-8')
    elif len(key) < 8:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(8 - len(key_bytes))
        key_bytes += extra_bytes

    elif len(key) > 8:
        key_bytes = key[:8].encode('utf-8')

    if len(vector) == 8:
        vector_bytes = vector.encode('utf-8')
    elif len(vector) < 8:
        #Generar el resto de bytes para el vector
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(8 - len(vector_bytes))
        vector_bytes += extra_bytes

    elif len(vector) > 8:
        vector_bytes = vector[:8].encode('utf-8')  

    decipher = DES.new(key_bytes, DES.MODE_CBC, vector_bytes)

    padded_text = decipher.decrypt(ciphertext)
    text_bytes = unpad(padded_text, DES.block_size)
    text = text_bytes.decode('utf-8')
    print("Texto descifrado con DES: ", text)

def alg_aes_decipher(key, vector, ciphertext):
    if len(key) == 16:
        key_bytes = key.encode('utf-8')
    elif len(key) < 16:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes

    elif len(key) > 16:
        key_bytes = key[:16].encode('utf-8')

    if len(vector) == 16:
        vector_bytes = vector.encode('utf-8')
    elif len(vector) < 16:
        #Generar el resto de bytes para el vector
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(vector_bytes))
        vector_bytes += extra_bytes

    elif len(vector) > 16:
        vector_bytes = vector[:16].encode('utf-8')  
    
    decipher = AES.new(key_bytes, AES.MODE_CBC, vector_bytes)

    padded_text = decipher.decrypt(ciphertext)

    text_bytes = unpad(padded_text, AES.block_size)
    text = text_bytes.decode('utf-8')
    print("Texto descifrado con AES: ", text)    

def alg_3des_decipher(key, vector, ciphertext):
    if len(key) == 16 or len(key) == 24:
        key_bytes = key.encode('utf-8')

    elif len(key) < 16:
        #Generar el resto de bytes para la clave
        key_bytes = key.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(key_bytes))
        key_bytes += extra_bytes

    elif len(key) > 16:
        key_bytes = key[:8].encode('utf-8')

    if len(vector) == 8:
        vector_bytes = vector.encode('utf-8')
    elif len(vector) < 8:
        #Generar el resto de bytes para el vector
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(8 - len(vector_bytes))
        vector_bytes += extra_bytes

    elif len(vector) > 8:
        vector_bytes = vector[:8].encode('utf-8')  

    decipher = DES3.new(key_bytes, DES3.MODE_CBC, vector_bytes)

    padded_text = decipher.decrypt(ciphertext)
    text_bytes = unpad(padded_text, DES3.block_size)
    text = text_bytes.decode('utf-8')
    print("Texto descifrado con DES3: ", text)      