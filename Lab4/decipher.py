import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


def des_decipher(key_bytes, iv_bytes, ciphertext_bytes):
    # Todo debe ser utilizado en bytes
    print("Mensaje a desencriptar: ", ciphertext_bytes)

    # Crear el objeto para el descifrado
    decipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)

    # Descifrar el mensaje
    deciphertext = decipher.decrypt(ciphertext_bytes)

    # Eliminar el padding
    deciphertext_unpadded = unpad(deciphertext, DES.block_size)
    print("El mensaje descifrado (sin padding): ", deciphertext_unpadded)

    return deciphertext_unpadded

def aes_decipher(key_bytes, iv_bytes, ciphertext_bytes):
    # Todo debe ser utilizado en bytes
    print("Mensaje a desencriptar: ", ciphertext_bytes)

    # Crear el objeto para el descifrado
    decipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    # Descifrar el mensaje
    deciphertext = decipher.decrypt(ciphertext_bytes)

    # Eliminar el padding
    deciphertext_unpadded = unpad(deciphertext, AES.block_size)
    print("El mensaje descifrado (sin padding): ", deciphertext_unpadded)

    return deciphertext_unpadded

def des3_decipher(key_bytes, iv_bytes, ciphertext_bytes):
    # Todo debe ser utilizado en bytes
    print("Mensaje a desencriptar: ", ciphertext_bytes)

    # Crear el objeto para el descifrado
    decipher = DES3.new(key_bytes, DES3.MODE_CBC, iv_bytes)

    # Descifrar el mensaje
    deciphertext = decipher.decrypt(ciphertext_bytes)

    # Eliminar el padding
    deciphertext_unpadded = unpad(deciphertext, DES3.block_size)
    print("El mensaje descifrado (sin padding): ", deciphertext_unpadded)

    return deciphertext_unpadded