import socket
from errno import ECONNREFUSED
from multiprocessing import Pool

host = "192.168.0.15"

def doWork(N):
    l = [i + N for i in range(0, 65534, 4)]
    pingList(l)


def ping(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        print(str(port) + " Port open")
        return port
    except socket.error as err:
        if err.errno == ECONNREFUSED:
            return False
        raise


def pingList(port):

    for x in port:
        ping(host, x)


if __name__ == '__main__':
    pool = Pool(processes=4)
    pool.map(doWork, (2,3,4,5))