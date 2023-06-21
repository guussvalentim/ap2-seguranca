from scapy.all import * 

arqInicializacao = 'netconf.txt'
arqLog = 'netlog.txt'

class analisadorDeRede:
    def __init__(self, arquivoInicializacao):
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
        
        print(self.ips_ativos)
        print(self.portas_ativas)

        linha2 = linha2.split(",")
        
        self.periodoTarefas = linha2[0]
        self.subrede = f"{linha2[1]}/24"
        self.ip_local = linha2[2]

    def analisePacotes(self, pacote):    
        if pacote != None:
            horario = time.strftime("%H:%M:%S", time.localtime(pacote.time))

        descricao = ""

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
            descricao = "-"


        descricao = f"Pacote enviado da camada de {camada} com protocolo {protocolo}, origem em {origem} com destino {destino}"

        return f"{horario}, {camada}, {protocolo}, {IP_host}, {origem}, {destino}", descricao

    def varrePortas(self):
            for ip in range(0,len(self.ips_ativos)):
                print(ip)
                for porta in self.portas_ativas[ip]:
                    print(porta)
                    
                    pkt = IP(dst=f"{self.ips_ativos[ip]}") / TCP(dport=int(porta), flags='S')

                    resposta = sr1(pkt, timeout=2, verbose=0)

                    if resposta:
                        if resposta.flags == "SA":
                            log, descricao = self.analisePacotes(resposta)
                            evento = "Rede"
                            descricao += f", com porta {porta} ativa e disponível."

                            yield f"{log}, {evento}, {descricao}\n" 
                        else:
                            log, descricao = self.analisePacotes(resposta)
                            evento = "Anomalia"
                            descricao += f", com porta {porta} indisponível."

                            yield f"{log}, {evento}, {descricao}\n"
                    else:
                        yield f"-, Transporte, TCP, {self.ips_ativos[ip]}, {porta}, -, Anomalia, Não foi possível estabelecer conexão com a porta."

                    

    
    def varreIps(self):            
        for i in range(1, 255):
            ip_addr = str(f"{self.subrede[:-4]}{i}")

            pacote = IP(dst=ip_addr)/ICMP()
            reply = sr1(pacote, timeout=2, verbose=0)

            if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                log, descricao = self.analisePacotes(reply)

                if ip_addr in self.ips_ativos:
                    evento = "Rede"
                    descricao += ", com IP remetente pertencente a rede"
                else:
                    evento = "Anomalia" 
                    descricao += ", com IP remetente fora da rede."

                yield f"{log}, {evento}, {descricao}\n" 

        
        
    


def main():
    analisador = analisadorDeRede(arqInicializacao)

    if os.path.exists(arqLog):
        modo = "a"
    else:
        modo = "w"

    while True:
        for log in analisador.varrePortas():
            with open(arqLog, modo) as file:
                file.write(log)

                file.close()
                modo = "a"
        for log in analisador.varreIps():
            with open(arqLog, modo) as file:
                print(log)  
                file.write(log)

                file.close()
                modo = "a"
        

        time.sleep(analisador.periodoTarefas)


        


main()