from scapy.all import sniff, IP, ICMP
import string
import sys
from colorama import Fore, Back, Style, init

init(autoreset=True)  # Inicializa colorama

def caesar_decrypt(text, shift):
    decrypted = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            decrypted += char
    return decrypted

def is_probable_text(text):
    # Lógica simple para determinar si el texto parece ser español
    common_words = ['el', 'la', 'de', 'que', 'y', 'en', 'un', 'ser', 'se', 'no', 'haber', 'por', 'con', 'su', 'para']
    word_count = sum(1 for word in text.lower().split() if word in common_words)
    return word_count >= 2  # Si contiene al menos 2 palabras comunes

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        payload = packet[ICMP].load.decode('utf-8', errors='ignore')
        hidden_data.append(payload)

print("Capturando paquetes ICMP... Presiona Ctrl+C para detener.")
hidden_data = []

try:
    sniff(filter="icmp", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nCaptura detenida.")

if not hidden_data:
    print("No se capturaron datos ocultos.")
    sys.exit(1)

encrypted_message = ''.join(hidden_data)
print(f"\nMensaje cifrado recuperado: {encrypted_message}")

print("\nPosibles mensajes descifrados:")
for shift in range(26):
    decrypted = caesar_decrypt(encrypted_message, shift)
    if is_probable_text(decrypted):
        print(Fore.GREEN + f"Rotación {shift}: {decrypted}")
    else:
        print(f"Rotación {shift}: {decrypted}")