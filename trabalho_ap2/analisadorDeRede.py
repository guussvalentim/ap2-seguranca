from scapy.all import * 

arqInicializacao = 'netconf.txt'

class analisadorDeRede:
    def __init__(self, arquivoInicializacao):
        print("init")
        arq = open(arquivoInicializacao, "r")

        self.ips_ativos = []
        self.portas_ativas = []

        linha1 = arq.readline()[:-1]
        
        linha2 = arq.readline()
        
        arq.close()

        linha1 = linha1.split(" - ")
        for ip in linha1:
            ip = ip.split(":")
            self.ips_ativos.append(ip[0])
            
            ip[1] = ip[1].split(",")
            self.portas_ativas.append(ip[1])
        

        linha2 = linha2.split(",")
        
        self.periodoTarefas = linha2[0]
        self.subrede = f"{linha2[1]}/24"
        self.ip_local = linha2[2]

    def analisePacotes(self, pacote):    
        horario = time.strftime("%H:%M:%S", time.localtime(pacote.time))
        evento = "-"
        descricao = evento

        if TCP in pacote or UDP in pacote:
            camada = "Transporte"
            if IP in pacote:
                IP_host = pacote[IP].src
            elif IPv6 in pacote:
                IP_host = pacote[IPv6].src
            
            if TCP in pacote:
                protocolo = "TCP"
                origem = pacote[TCP].sport
                destino = pacote[TCP].dport
            elif UDP in pacote:
                protocolo = "UDP"
                origem = pacote[UDP].sport
                destino = pacote[UDP].dport
        elif IP in pacote or IPv6 in pacote:
            camada = "Rede"
            if IP in pacote:
                protocolo = "IP"
                IP_host = pacote[IP].src
                origem = IP_host
                destino = pacote[IP].dst
            elif IPv6 in pacote:
                protocolo = "IPv6"
                IP_host = pacote[IPv6].src
                origem = IP_host
                destino = pacote[IPv6].dst
        elif Ether in pacote:
            camada = "Enlace"
            protocolo = "Ether"
            IP_host = "-"
            origem = pacote[Ether].src
            destino = pacote[Ether].dst

        else:
            camada = "Desconhecida"
            protocolo = "-"
            IP_host = "-"
            origem = "-"
            destino = "-"
            evento = "-"
            descricao = "-"

        if IP_host in self.ips_ativos:
            evento = "Rede"
        else:
            evento = "Anomalia"
        

        return f"{horario}, {camada}, {protocolo}, {IP_host}, {origem}, {destino}, {evento}, {descricao}"


    
    def capturaPacotes(self):
        while True:
            time.sleep(int(self.periodoTarefas))
            
            for i in range(1, 255):
                ip_addr = str(f"{self.subrede[:-4]}{i}")

                pacote = IP(dst=ip_addr)/ICMP()
                reply = sr1(pacote, timeout=2, verbose=0)
                
                if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                    log = self.analisePacotes(reply)

                    yield log

        
    


def main():
    analisador = analisadorDeRede(arqInicializacao)

    for log in analisador.capturaPacotes():
        print(log)

main()