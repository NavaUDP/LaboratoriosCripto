from scapy.all import sniff, IP, ICMP
import time
from colorama import Fore, init
import string

init(autoreset=True)  # Inicializa colorama

TARGET_IP = "64.233.190.101"  # La IP de destino usada en pingv4.py
TIMEOUT = 30  # Tiempo de espera en segundos después del último paquete

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
    common_words = ['el', 'la', 'de', 'que', 'y', 'en', 'un', 'ser', 'se', 'no', 'haber', 'por', 'con', 'su', 'para']
    word_count = sum(1 for word in text.lower().split() if word in common_words)
    return word_count

def packet_callback(packet):
    global last_packet_time
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].dst == TARGET_IP:
        payload = packet[ICMP].load.decode('utf-8', errors='ignore')
        hidden_char = payload[-1]  # Solo tomamos el último carácter
        hidden_data.append(hidden_char)
        print(f"Carácter capturado: {hidden_char}")
        last_packet_time = time.time()

print(f"Capturando paquetes ICMP Request enviados a {TARGET_IP}...")
print(f"La captura se detendrá automáticamente después de {TIMEOUT} segundos sin recibir paquetes.")
print("Puedes presionar Ctrl+C para detener manualmente.")

hidden_data = []
last_packet_time = time.time()

try:
    while True:
        sniff(filter=f"icmp and dst host {TARGET_IP}", prn=packet_callback, store=0, timeout=1)
        if time.time() - last_packet_time > TIMEOUT:
            print("\nNo se han recibido paquetes en los últimos 30 segundos. Finalizando captura.")
            break
except KeyboardInterrupt:
    print("\nCaptura detenida manualmente.")

if not hidden_data:
    print("No se capturaron datos ocultos.")
    exit(1)

encrypted_message = ''.join(hidden_data)
print(f"\nMensaje cifrado recuperado: {encrypted_message}")

print("\nPosibles interpretaciones del mensaje:")

# Generamos todas las rotaciones posibles
possible_messages = [caesar_decrypt(encrypted_message, shift) for shift in range(26)]

# Evaluamos la probabilidad de cada mensaje
probabilities = [is_probable_text(msg) for msg in possible_messages]

# Encontramos el mensaje más probable
most_probable_index = probabilities.index(max(probabilities))

# Imprimimos todas las opciones, resaltando la más probable
for i, msg in enumerate(possible_messages):
    if i == most_probable_index:
        print(Fore.GREEN + f"Rotación {i}: {msg}")
    else:
        print(f"Rotación {i}: {msg}")

print(f"\nLa interpretación más probable es: {Fore.GREEN + possible_messages[most_probable_index]}")