import socket
import threading

bind_ip = "127.0.0.1"
bind_port = 9998

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server.bind((bind_ip, bind_port))

print("[*] Listening on %s:%d" % (bind_ip, bind_port))


def handle_client(client_socket):

    data, addr = client_socket.recv(4096)

    print("[*] Received: %s" % data)

    client_socket.send("ACK!".encode())

    client_socket.close()


while True:

    client, addr = server.accept()

    print("[*] Accepted Connection from: %s:%d" % (addr[0],addr[1]))

    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()