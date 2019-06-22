import threading
import time
import socket
from ctypes import *
import struct
from netaddr import IPNetwork, IPAddress
import ctypes

# host to listen on
HOST = '192.168.0.4'
# subnet to target (iterates through all IP address in this subnet)
SUBNET = '192.168.0.0/24'
# string signature
MESSAGE = 'hellooooo'


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, buffer):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer):
        pass


# sprays out the udp datagram
def udp_sender(SUBNET, MESSAGE):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(SUBNET):
        try:
            sender.sendto(MESSAGE, ("%s" % ip, 65212))
        except:
            pass


def main():
    t = threading.Thread(target=udp_sender, args=(SUBNET, MESSAGE))
    t.start()

    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # continually read in packets and parse their information
    while 1:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_addr = socket.inet_ntoa(iph[8])

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        # check for the type 3 and code and within our target subnet
        if icmp_header.code == 0 and icmp_header.type == 0:
            if IPAddress(src_addr) in IPNetwork(SUBNET):
                if raw_buffer[len(raw_buffer) - len(MESSAGE):] == MESSAGE:
                    print("Host up: %s" % src_addr)


if __name__ == '__main__':
    main()