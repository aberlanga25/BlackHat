import socket

target_host = "localhost"
target_port = 8000

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client.sendto("AAAABBBCCC".encode(), (target_host,target_port))

data, addr = client.recvfrom(4096)

if data:
    print(data)
#print(addr)