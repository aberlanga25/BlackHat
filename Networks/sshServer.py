import socket
import paramiko
import threading
import sys

host_key = paramiko.RSAKey(filename='test_rsa.key')


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        if (username == 'b') and (password == '123'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


server = sys.argv[1]
ssh_port = int(sys.argv[2])

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server, ssh_port))
    sock.listen(100)
    print("[+] Listening for connection ...")
    client, addr = sock.accept()

except Exception as e:
    print(f"[-] Listen failed: {str(e)}")
    sys.exit(1)

print("[+] Got a connection!")

try:
    session = paramiko.Transport(client)
    session.add_server_key(host_key)
    server = Server()

    try:
        session.start_server(server=server)
    except paramiko.SSHException as x:
        print("[-] SSH negotiation failed.")

    chan = session.accept(20)
    print("[+] Authenticated.")
    print(chan.recv(1024))
    chan.send('Welcome to b_ssh')
    while True:
        try:
            command = input("Enter command: ")
            if command != 'exit':
                chan.send(command)
                print(str(chan.recv(1024),'utf-8'))
            else:
                chan.send('exit')
                print('exiting')
                session.close()
                raise Exception('exit')
        except KeyboardInterrupt:
            session.close()
except Exception as e:
    print(f"[-] Caught exception: {str(e)}")
    try:
        session.close()
    except:
        pass
    sys.exit(1)
