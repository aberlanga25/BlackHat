import sys
import socket
import threading

def server_loop(lhost, lport, rhost, rport, receive_first):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((lhost, lport))
    except:
        print("[!!] Failed to listen on %s:%d" % (lhost, lport))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s%d" % (lhost,lport))

    server.listen(5)

    while True:
        client_scoket, addr = server.accept()

        print("[==>] Received incoming connection from %s:%d" % (addr[0], addr[1]))

        proxy_thread = threading.Thread(target=proxy_handler, args=(client_scoket, rhost, rport, receive_first))
        proxy_thread.start()

def main():
