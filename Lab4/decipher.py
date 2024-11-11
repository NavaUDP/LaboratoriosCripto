import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

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

#no funciona correctamente
def alg_aes_decipher(key, vector, ciphertext_base64):
    if len(key) == 16:
        key_bytes = key.encode('utf-8')
    elif len(key) < 16:
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
        vector_bytes = vector.encode('utf-8')
        extra_bytes = get_random_bytes(16 - len(vector_bytes))
        vector_bytes += extra_bytes
        print("vector de inicializacion modificado: ", vector_bytes)
    elif len(vector) > 16:
        vector_bytes = vector[:16].encode('utf-8')
        print("vector de inicializacion modificado: ", vector_bytes)

    ciphertext = base64.b64decode(ciphertext_base64)

    decipher = AES.new(key_bytes, AES.MODE_CBC, vector_bytes)
    padded_text = decipher.decrypt(ciphertext)
    text_bytes = unpad(padded_text, AES.block_size)
    text = text_bytes.decode('utf-8')
    print("Texto descifrado con AES: ", text)
    return text

#no funciona correctamente
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