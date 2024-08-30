from scapy.all import IP, ICMP, Raw, send, sr1
import sys
import time
import struct
import os

def send_ping_with_hidden_data(destination, data):
    print(f"Enviando datos ocultos a {destination}:")
    
    sequence = 0
    identifier = os.getpid() & 0xFFFF  # Usa el PID como identificador
    
    # Payload ICMP constante (8 primeros bytes)
    icmp_payload_header = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    
    # Payload ICMP constante (0x10 a 0x37)
    icmp_payload_data = bytes.fromhex('10' * 40)
    
    for char in data:
        # Creamos un timestamp consistente
        timestamp = struct.pack("!Q", int(time.time() * 1000))
        
        # Creamos el payload completo
        full_payload = icmp_payload_header + timestamp + icmp_payload_data + char.encode()
        
        # Creamos un paquete ICMP con el payload completo
        packet = IP(dst=destination)/ICMP(type="echo-request", id=identifier, seq=sequence)/Raw(load=full_payload)
        
        # Enviamos el paquete y esperamos la respuesta
        reply = sr1(packet, timeout=2, verbose=False)
        
        if reply:
            print(f"Carácter '{char}' enviado exitosamente. Secuencia: {sequence}, ID: {identifier}")
        else:
            print(f"No se recibió respuesta para el carácter '{char}'. Secuencia: {sequence}, ID: {identifier}")
        
        # Incrementamos la secuencia y la id
        sequence += 1
        identifier += 1
        
        # Esperamos un poco para no saturar la red
        time.sleep(0.5)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py <texto_cifrado>")
        sys.exit(1)

    texto_cifrado = sys.argv[1]
    destination = "64.233.190.101"  # IP de Google como ejemplo

    send_ping_with_hidden_data(destination, texto_cifrado)