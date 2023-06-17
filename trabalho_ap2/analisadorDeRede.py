import scapy.all as scapy


class analisadorDeRede():
    def __init__(self, arquivoInicializacao, periodoTarefas):
        self.arquivo = open(arquivoInicializacao, "r")
        self.periodicidade = periodoTarefas
        
