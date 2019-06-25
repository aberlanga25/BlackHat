from scapy.all import *

def packet_callback(packet):

    if packet[TCP_SERVICES].payload:

        mpacket = str(packet[TCP_SERVICES].payload)

        print("[*] Server: %s" % packet[IPField].dst)
        print("[*] %s" % packet[TCP_SERVICES].payload)


sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback,store=0)