from scapy.all import *

capture = sniff(count=5)
capture.show()
for pkt in capture:
    pkt.show()