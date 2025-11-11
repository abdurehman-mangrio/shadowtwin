#!/usr/bin/env python3
"""
Network Reconnaissance Engine
Discovers networks, clients, and gathers intelligence
"""

from scapy.all import *
import threading
import time
import json
from colorama import Fore, Style
import logging
from collections import defaultdict

class ReconnaissanceEngine:
    def __init__(self, interface):
        self.interface = interface
        self.is_scanning = False
        self.networks = {}
        self.clients = defaultdict(list)
        self.probe_requests = []
        self.handshakes = []
        self.logger = logging.getLogger('recon_engine')
    
    def packet_handler(self, packet):
        """Handle captured packets for reconnaissance"""
        try:
            # Beacon frames (AP advertisements)
            if packet.haslayer(Dot11Beacon):
                self.process_beacon(packet)
            
            # Probe requests (clients looking for networks)
            elif packet.haslayer(Dot11ProbeReq):
                self.process_probe_request(packet)
            
            # Data frames (client activity)
            elif packet.haslayer(Dot11) and packet.type == 2:
                self.process_data_frame(packet)
                
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def process_beacon(self, packet):
        """Process beacon frames to discover networks"""
        if not packet.haslayer(Dot11Elt):
            return
        
        # Extract MAC address
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet[Dot11Elt].info else "<hidden>"
        
        # Extract capabilities
        capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        crypto = self.parse_crypto(capabilities, packet)
        
        # Extract channel
        channel = None
        while packet.haslayer(Dot11Elt):
            packet = packet[Dot11Elt]
            if packet.ID == 3:  # DS Parameter set (channel)
                channel = ord(packet.info)
                break
            if not packet.payload or not hasattr(packet.payload, 'ID'):
                break
        
        # Extract signal strength
        if packet.haslayer(RadioTap):
            signal = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -100
        else:
            signal = -100
        
        # Store network information
        network_info = {
            'ssid': ssid,
            'bssid': bssid,
            'channel': channel,
            'signal': signal,
            'crypto': crypto,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'beacon_count': 1
        }
        
        if bssid in self.networks:
            # Update existing network
            self.networks[bssid]['last_seen'] = time.time()
            self.networks[bssid]['beacon_count'] += 1
            if signal > self.networks[bssid]['signal']:
                self.networks[bssid]['signal'] = signal
        else:
            # New network
            self.networks[bssid] = network_info
            print(f"{Fore.GREEN}[+] Discovered network: {ssid} ({bssid}) - Channel {channel} - {crypto}{Style.RESET_ALL}")
    
    def process_probe_request(self, packet):
        """Process probe requests to discover clients"""
        client_mac = packet[Dot11].addr2
        
        # Extract SSID from probe request
        ssid = None
        if packet.haslayer(Dot11Elt):
            ssid_element = packet[Dot11Elt]
            if ssid_element.info:
                ssid = ssid_element.info.decode('utf-8', errors='ignore')
        
        probe_info = {
            'client_mac': client_mac,
            'ssid': ssid,
            'timestamp': time.time(),
            'signal': packet[RadioTap].dBm_AntSignal if packet.haslayer(RadioTap) else -100
        }
        
        self.probe_requests.append(probe_info)
        
        # Track client
        if ssid:
            if client_mac not in self.clients:
                print(f"{Fore.YELLOW}[+] Discovered client: {client_mac} - Looking for: {ssid}{Style.RESET_ALL}")
            self.clients[client_mac].append(ssid)
    
    def process_data_frame(self, packet):
        """Process data frames to associate clients with APs"""
        if packet.addr1 and packet.addr2:  # Check if addresses exist
            # Client to AP communication
            if packet.addr1 in self.networks:  # AP is destination
                client_mac = packet.addr2
                ap_bssid = packet.addr1
                self.associate_client(client_mac, ap_bssid)
            
            # AP to client communication
            elif packet.addr2 in self.networks:  # AP is source
                client_mac = packet.addr1
                ap_bssid = packet.addr2
                self.associate_client(client_mac, ap_bssid)
    
    def associate_client(self, client_mac, ap_bssid):
        """Associate client with AP"""
        if ap_bssid in self.networks:
            network = self.networks[ap_bssid]
            if client_mac not in network.get('clients', []):
                if 'clients' not in network:
                    network['clients'] = []
                network['clients'].append(client_mac)
                print(f"{Fore.CYAN}[+] Client {client_mac} associated with {network['ssid']}{Style.RESET_ALL}")
    
    def parse_crypto(self, capabilities, packet):
        """Parse encryption type from capabilities"""
        crypto = "OPEN"
        
        # Check for WEP
        if "privacy" in capabilities:
            crypto = "WEP"
        
        # Check for WPA/WPA2
        if packet.haslayer(Dot11Elt):
            p = packet
            while p.haslayer(Dot11Elt):
                if p[Dot11Elt].ID == 48:  # RSN Information
                    crypto = "WPA2"
                    break
                elif p[Dot11Elt].ID == 221:  # Vendor Specific
                    if p[Dot11Elt].info.startswith(b'\x00\x50\xf2\x01\x01\x00'):
                        crypto = "WPA"
                        break
                p = p.payload
        
        return crypto
    
    def start_scan(self, duration=60):
        """Start network reconnaissance"""
        print(f"{Fore.CYAN}[*] Starting network reconnaissance on {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Duration: {duration} seconds{Style.RESET_ALL}")
        
        self.is_scanning = True
        start_time = time.time()
        
        def stop_scan():
            time.sleep(duration)
            self.is_scanning = False
        
        # Start timeout thread
        timeout_thread = threading.Thread(target=stop_scan)
        timeout_thread.daemon = True
        timeout_thread.start()
        
        # Start packet capture
        try:
            sniff(iface=self.interface, 
                  prn=self.packet_handler, 
                  stop_filter=lambda x: not self.is_scanning,
                  timeout=duration)
        except Exception as e:
            print(f"{Fore.RED}[-] Error during scan: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Reconnaissance completed{Style.RESET_ALL}")
        self.print_summary()
    
    def passive_scan(self, duration=60):
        """Passive scanning (listen only)"""
        self.start_scan(duration)
    
    def active_scan(self):
        """Active scanning (probe requests)"""
        print(f"{Fore.CYAN}[*] Starting active scan{Style.RESET_ALL}")
        # Note: Active scanning requires sending probe requests
        # This is more complex and may be detected
        print(f"{Fore.YELLOW}[!] Active scan not fully implemented{Style.RESET_ALL}")
    
    def comprehensive_scan(self):
        """Comprehensive scan with multiple techniques"""
        print(f"{Fore.CYAN}[*] Starting comprehensive scan{Style.RESET_ALL}")
        self.start_scan(duration=120)
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}            RECONNAISSANCE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}Networks Discovered: {len(self.networks)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Clients Discovered: {len(self.clients)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Probe Requests: {len(self.probe_requests)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}TOP NETWORKS:{Style.RESET_ALL}")
        sorted_networks = sorted(self.networks.values(), 
                               key=lambda x: x['signal'], 
                               reverse=True)[:10]
        
        for i, net in enumerate(sorted_networks, 1):
            clients = len(net.get('clients', []))
            print(f"  {i}. {net['ssid']} - {net['bssid']} - Ch{net['channel']} - {net['crypto']} - {clients} clients")
        
        print(f"\n{Fore.YELLOW}TOP CLIENTS:{Style.RESET_ALL}")
        sorted_clients = sorted(self.clients.items(), 
                              key=lambda x: len(x[1]), 
                              reverse=True)[:10]
        
        for i, (client, ssids) in enumerate(sorted_clients, 1):
            unique_ssids = list(set(ssids))
            print(f"  {i}. {client} - Looking for: {', '.join(unique_ssids[:3])}")
    
    def export_results(self, filename=None):
        """Export scan results to JSON"""
        if not filename:
            filename = f"recon_scan_{int(time.time())}.json"
        
        results = {
            'timestamp': time.time(),
            'networks': self.networks,
            'clients': dict(self.clients),
            'probe_requests': self.probe_requests
        }
        
        with open(f"logs/intelligence/{filename}", 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] Scan results exported to: logs/intelligence/{filename}{Style.RESET_ALL}")
    
    def get_network_by_ssid(self, ssid):
        """Get network information by SSID"""
        for net in self.networks.values():
            if net['ssid'] == ssid:
                return net
        return None
    
    def get_client_networks(self, client_mac):
        """Get networks a client is looking for"""
        return self.clients.get(client_mac, [])