from scapy.all import *

def enviar_segmento_udp(dest_ip, dest_port):
    src_port = RandShort()
    segmento = IP(dst=dest_ip) / UDP(dport=dest_port)
    resposta = sr1(segmento, timeout=1, verbose=0)
    
    if resposta is None:
        print(f"A porta {dest_port} está filtrada ou fechada.")
    elif resposta.haslayer(UDP):
        print(f"A porta {dest_port} está aberta.")
    elif resposta.haslayer(ICMP) and resposta.getlayer(ICMP).type == 3 and resposta.getlayer(ICMP).code in [1, 2, 9, 10, 13]:
        print(f"A porta {dest_port} está filtrada.")
    elif resposta.haslayer(ICMP) and resposta.getlayer(ICMP).type == 3 and resposta.getlayer(ICMP).code == 3:
        print(f"A porta {dest_port} está fechada.")
    else:
        print(f"Resposta inesperada para a porta {dest_port}.")

def escanear_portas(dest_ip, dest_ports):
    for port in dest_ports:
        enviar_segmento_udp(dest_ip, port)

dest_ip = "127.0.0.1"
dest_ports = [0, 1, 2, 12000]  # Substitua pelas portas que deseja escanear
escanear_portas(dest_ip, dest_ports)
