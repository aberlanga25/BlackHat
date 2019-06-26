from scapy.all import *

def packet_callback(packet):

    if packet[TCP].payload:

        mpacket = str(packet[TCP].payload)

        print("[*] Server: %s" % packet[IP].dst)
        print("[*] %s" % packet[TCP].payload)


sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback,store=0)