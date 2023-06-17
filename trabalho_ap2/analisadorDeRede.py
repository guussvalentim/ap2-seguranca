from scapy.all import *
import datetime 


def __init__(self, arquivoInicializacao, periodoTarefas):
    self.arquivo = open(arquivoInicializacao, "r")
    self.periodicidade = periodoTarefas
        
    
def analisePacotes(pacote):
    horario = datetime.datetime.now().strftime("%H:%M:%S")
        
    if TCP in pacote or UDP in pacote:
        camada = "Transporte"
        if TCP in pacote:
            protocolo = "TCP"
        elif UDP in pacote:
            protocolo = "UDP"
                
    elif IP in pacote or IPv6 in pacote:
        IP_host = pacote[IP].src
        camada = "Rede"
    elif Ether in pacote:
        camada = "Enlace"
    else:
        camada = "Desconhecida"

    yield f"{horario}, {camada}, {protocolo}, {IP_host}, {origem}, {destino}, {anomalia}, {descricao}"

