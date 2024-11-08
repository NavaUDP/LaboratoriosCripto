from algoritmos import alg_aes_256, alg_des, alg_3des, alg_des_decipher, alg_aes_decipher, alg_3des_decipher

#Solicitar los datos al usuario
print("Indique el algoritmo a utilizar: ")
print("1. DES")
print("2. AES")
print("3. 3DES")

algoritmo = input("-> ")

key = input("Ingrese la clave a utilizar: ")
vector = input("Ingrese el vector de inicializacion (IV): ")
text = input("Ingrese el texto a cifrar: ")

if algoritmo == "1":
    texto_cifrado_des = alg_des(key, vector, text)
    cifrado = input("Pulse enter para descifrar el mensaje.")

    if cifrado is None:
        alg_des_decipher(key, vector, texto_cifrado_des)
    else: 
        alg_des_decipher(key, vector, texto_cifrado_des)
elif algoritmo == "2":
    texto_cifrado_aes = alg_aes_256(key, vector, text)
    cifrado = input("Pulse enter para descifrar el mensaje.")

    if cifrado is None:
        alg_aes_decipher(key, vector, texto_cifrado_aes)
    else: 
        alg_aes_decipher(key, vector, texto_cifrado_aes)

elif algoritmo == "3":
    texto_cifrado_3des = alg_des(key, vector, text)
    cifrado = input("Pulse enter para descifrar el mensaje.")

    if cifrado is None:
        alg_3des_decipher(key, vector, texto_cifrado_3des)
    else: 
        alg_3des_decipher(key, vector, texto_cifrado_3des)


