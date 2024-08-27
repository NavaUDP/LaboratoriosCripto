import sys

def cesar_cipher(text, shift, mode='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            if mode == 'encrypt':
                new_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                new_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            result += new_char
        else:
            result += char
    return result


if len(sys.argv) != 4:
    print("Uso: python3 cesar.py <texto> <desplazamiento> <texto_cifrado>")
    sys.exit(1)

texto = sys.argv[1]
desplazamiento = int(sys.argv[2])
texto_cifrado = sys.argv[3]

# Cifrar el texto
resultado_cifrado = cesar_cipher(texto, desplazamiento)
print(f"Texto cifrado: {resultado_cifrado}")

# Verificar si el texto cifrado coincide con el proporcionado
if resultado_cifrado == texto_cifrado:
    print("El texto cifrado coincide con el proporcionado.")
else:
    print("El texto cifrado no coincide con el proporcionado.")

# Descifrar el texto cifrado proporcionado
texto_descifrado = cesar_cipher(texto_cifrado, desplazamiento, mode='decrypt')
print(f"Texto descifrado: {texto_descifrado}")