import sys
import socket
import threading
import csv

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

    if len(sys.argv[1:]) != 5:
        print("Usage: tcpProxy [localhost] [localport] [remotehost] [remoteport] [receiveFirst]")
        sys.exit(0)

    lhost = sys.argv[1]
    lport = int(sys.argv[2])

    rhost = sys.argv[3]
    rport = int(sys.argv[4])

    receivefirst = sys.argv[5]

    if "True" in receivefirst:
        receivefirst = True
    else:
        receivefirst = False

    server_loop(lhost, lport, rhost, rport, receivefirst)

def proxy_handler(clientsocket, rhost, rport, receivefirst):

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((rhost, rport))

    if receivefirst:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        remote_buffer = response_handler(remote_buffer)

        if len(remote_buffer):
            print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
            clientsocket.send(remote_buffer)

    while True:

        localbuffer = receive_from(clientsocket)

        if len(localbuffer):
            print("[==>] Received %d bytes to localhost." % len(localbuffer))
            hexdump(localbuffer)

            localbuffer = request_handler(localbuffer)

            remote_socket.send(localbuffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)

            clientsocket.send(remote_buffer)

            print("[<==] Sent to localhost.")

        if not len(localbuffer) or not len(remote_buffer):
            clientsocket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections")

            break


def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, str) else 2

    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" & (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X %-*s %s" % (i, length*(digits+1), hexa, text))

    print(b'\n'.join(result))


def receive_from(connection):

    buffer = ""

    connection.settimeout(2)

    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break

            buffer+= data
    except:
        pass

    return buffer


def request_handler(buffer):
    return buffer

def response_handler(buffer):
    return buffer

main()