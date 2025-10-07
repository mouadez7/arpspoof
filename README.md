# arpspoof.py

ARP Spoofing Tool using Scapy

Description
-----------
Simple ARP spoofing / ARP ban demonstration script — an enhanced version of the script from the iconic book Black Hat Python (Chapter 4), adapted for educational lab use.
Usage
-----
Usage: sudo python3 arpspoof.py -t TARGET -g GATEWAY -i INTERFACE -s|-b

Required Arguments:
  -t, --target_ip    Target IP address to spoof
  -g, --gateway_ip   Gateway/Router IP address
  -i, --interface    Network interface

Operation Mode:
  -s, --spoof        ARP spoofing mode (man-in-the-middle)
  -b, --ban          ARP ban mode (denial of service)

Examples:
  sudo python3 arpspoof.py -t 192.168.1.7 -g 192.168.1.1 -i eth0 -s
  sudo python3 arpspoof.py -t 192.168.1.7 -g 192.168.1.1 -i eth0 -b