import os
import tempfile
import subprocess

class RogueAP:
    def __init__(self, interface, ssid, channel=6, password="testpass123"):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.password = password

    def start(self):
        config = f"""
interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
        """

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as conf:
            conf.write(config)
            self.conf_path = conf.name

        print(f"[+] Launching HostAPd from config: {self.conf_path}")
        subprocess.run(["sudo", "hostapd", self.conf_path])