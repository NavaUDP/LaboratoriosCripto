from algoritmos import alg_aes_256, alg_des, alg_3des, alg_des_decipher, alg_aes_decipher, alg_3des_decipher

#Solicitar los datos al usuario
print("Bienvenido, ingrese los siguientes datos:")

key = input("Ingrese la clave a utilizar: ")
vector = input("Ingrese el vector de inicializacion (IV): ")
text = input("Ingrese el texto a cifrar: ")

cifrado = True

while cifrado == True:
    #Algoritmo DES
    print("Cifrado DES")
    ciphertext = alg_des(key, vector, text)
    descifrado = input("Desea descifrar el texto cifrado con DES? (1.- Si/2.- No): ")

    if descifrado == "1":
        alg_des_decipher(key, vector, ciphertext)
    else: 
        print("Continua al cifrado AES...")
    
    print("Cifrado AES-256: ")
    ciphertext = alg_aes_256(key, vector, text)
    descifrado = input("Desea descifrar el texto cifrado con AES-256? (1.- Si/2.- No): ")

    if descifrado == "1":
        alg_aes_decipher(key, vector, ciphertext)
    else:
        print("Continua al cifrado 3DES...")

    print("Cifrado 3DES: ")
    ciphertext = alg_3des(key, vector, text)
    descifrado = input("Desea descifrar el texto cifrado con 3DES? (1.- Si/2.- No): ")

    if descifrado == "1":
        alg_3des_decipher(key, vector, ciphertext)
    else:
        break

    cifrado = False

