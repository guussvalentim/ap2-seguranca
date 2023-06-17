from socket import *

port = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)

serverSocket.bind(("0.0.0.0", port))

while True:
    data, addr = serverSocket.recvfrom(1024)
    response = data.decode().upper()
    serverSocket.sendto(response.encode(), addr)