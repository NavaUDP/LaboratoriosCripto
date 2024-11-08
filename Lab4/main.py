from algoritmos import alg_aes_256, alg_des, alg_3des, alg_des_decipher

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
    texto_cifrado = alg_des(key, vector, text)
    cifrado = input("Pulse enter para descifrar el mensaje.")
    if cifrado is None:
        alg_des_decipher(key, vector, texto_cifrado)
    else: 
        alg_des_decipher(key, vector, texto_cifrado)
elif algoritmo == "2":
    alg_aes_256()
elif algoritmo == "3":
    alg_3des()


