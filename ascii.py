#pasa de hexadecimal a ascii

def hex_to_ascii():
    text_chain = []

    with open('encrypted1.txt', 'r') as archivo:

        for char in archivo.read():
            ascii_char = ord(char) + 2
            text_chain.append(chr(ascii_char))
    
    resultado = ''.join(text_chain)

    return resultado

print(hex_to_ascii())



    