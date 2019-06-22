import os
from ctypes import *
import socket
import struct
import sys
import threading
import time
from netaddr import IPNetwork, IPAddress


class IP(Structure):

    _fields_ = [
        ("ihl", c_uint8, 4),
        ("version", c_uint8, 4),
        ("tos", c_uint8),
        ("len", c_uint16),
        ("id", c_uint16),
        ("offset", c_uint16),
        ("ttl", c_uint8),
        ("protocol_num", c_uint8),
        ("sum", c_uint16),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


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

def udp_sender(subnet, msg):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(msg,("%s" % ip, 65212))
        except:
            pass

if __name__ == '__main__':

    # this should look familiar from the previous example
    if not len(sys.argv[1:]):
        host = "127.0.0.1"
        subnet = "192.168.0.0/24"
    else:
        host = sys.argv[1]
        subnet = sys.argv[2]

    msg = "B"

    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    t = threading.Thread(target=udp_sender, args=(subnet, msg))
    t.start()

    try:
        while True:
            # read in a packet
            raw_buffer = sniffer.recvfrom(65535)[0]

            # create an IP header from the first 20 bytes of the buffer
            ip_header = IP(raw_buffer[0:20])

            # print out the protocol that was detected and the hosts
            print("Protocol: {} {} -> {}".format(
                ip_header.protocol, ip_header.src_address, ip_header.dst_address
            ))

            if ip_header.protocol == "ICMP":

                offset = ip_header.ihl * 4

                buf = raw_buffer[offset:offset + sizeof(ICMP)]

                icmp_header = ICMP(buf)

                print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

                if icmp_header.code == 3 and icmp_header.type == 3:
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                        if raw_buffer[len(raw_buffer)-len(msg):] == msg:
                            print("Host Up: %s" % ip_header.src_address)

    except KeyboardInterrupt:
        # if we're using Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)