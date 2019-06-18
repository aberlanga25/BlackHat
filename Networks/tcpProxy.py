import sys
import socket
import threading

def server_loop(lhost, lport, rhost, rport, receivefirst):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((lhost, lport))
    except:
        print(f"[!!] Failed to listen on {lhost}:{lport}")
        print("[!!] Check for other listening sockets or correct permissions")
        sys.exit(0)

    print(f"[*] Listening on {lhost}:{lport}")

    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        print(f"[==>] Received incoming connection from {addr[0]}:{addr[1]}")

        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, rhost, rport, receivefirst))

        proxy_thread.start()

def main():

    if len(sys.argv[1:]) != 5:
        print("Usage: ./tcpproxy.py [localhost] [localport] [remotehost] "
              "[remoteport] [receive_first]")
        print("Example: ./tcpptoxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    lhost = sys.argv[1]
    lport = int(sys.argv[2])

    rhost = sys.argv[3]
    rport = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(lhost, lport, rhost, rport, receive_first)

def proxy_handler(client_socket, rhost, rport, receive_first):

    remote_socket =  socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    remote_socket.connect((rhost, rport))

    if receive_first:

        rbuffer = receive_from(remote_socket)
        hexdump(rbuffer)

        rbuffer = response_handler(rbuffer)

        if len(rbuffer):
            print(f"[<==] Sending {len(rbuffer)} bytes to localhost.")
            client_socket.send(rbuffer)

    while True:

        lbuffer = receive_from(client_socket)

        if len(lbuffer):
            print(f"[==>] Received {len(lbuffer)} bytes from localhost.")
            hexdump(lbuffer)

            lbuffer = request_handler(lbuffer)

            remote_socket.send(lbuffer)

            remote_socket.send(lbuffer)
            print("[==>] Sent to remote.")

        rbuffer = receive_from(remote_socket)

        if len(rbuffer):
            print(f"[<==] Received {len(rbuffer)} bytes from remote.")
            hexdump(rbuffer)

            rbuffer = response_handler(rbuffer)

            client_socket.send(rbuffer)

            print("[<==] Sent to localhost.")

        if not len(lbuffer) or not len(rbuffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data, Closing connections.")

            break

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, str) else 2

    for i in range(0, len(src), length):
        s = src[i:i + length]

        hexa = " ".join(map("{0:0>2X}".format, s))
        text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in s])
        result.append("%04X   %-*s   %s" % (i, length * (digits+1), hexa, text))
    print("\n".join(result))

def receive_from(connection):
    buffer = b""

    connection.settimeout(2)

    try:

        count = 0
        while True:
            count += 1
            data = connection.recv(4096)

            if not data:
                break
            buffer += data

    except:
        pass

    return  buffer


def request_handler(buffer):
    return buffer

def response_handler(buffer):
    return buffer

main()