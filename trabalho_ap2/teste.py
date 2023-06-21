from scapy.all import *

pkt = IP(dst = "192.168.15.119") / TCP(dport = 12000, flags = "S")

resposta = sr1(pkt, timeout = 2, verbose = 0)


if resposta and resposta.flags == "SA":
    print("SA")
else:
    print("merda")