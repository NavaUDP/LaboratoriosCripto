from algoritmos import alg_aes_256, alg_des

#Solicitar los datos al usuario
print("Indique el algoritmo a utilizar: ")
print("1. DES")
print("2. AES")
print("3. 3DES")

algoritmo = input("-> ")

if algoritmo == "1":
    alg_des()
elif algoritmo == "2":
    alg_aes_256()


