"""
Utility functions for ShadowTwin
"""

import os
import sys
import subprocess
import platform
from colorama import Fore, Style

def check_platform():
    """Check if running on Linux"""
    return platform.system().lower() == 'linux'

def check_dependencies():
    """Check for required system dependencies"""
    required_cmds = ['hostapd', 'dnsmasq', 'airmon-ng', 'airodump-ng']
    missing = []
    
    for cmd in required_cmds:
        try:
            subprocess.run(['which', cmd], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            missing.append(cmd)
    
    return missing

def run_command(cmd, sudo=False):
    """Run system command safely"""
    try:
        if sudo:
            cmd = ['sudo'] + cmd
            
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] Command failed: {e}{Style.RESET_ALL}")
        return None

def get_wireless_interfaces():
    """Get available wireless interfaces"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                iface = line.split()[0]
                interfaces.append(iface)
        return interfaces
    except Exception as e:
        print(f"{Fore.RED}[-] Error getting interfaces: {e}{Style.RESET_ALL}")
        return []

def enable_monitor_mode(interface):
    """Enable monitor mode on interface"""
    print(f"{Fore.CYAN}[*] Enabling monitor mode on {interface}{Style.RESET_ALL}")
    
    # Stop interfering processes
    run_command(['airmon-ng', 'check', 'kill'], sudo=True)
    
    # Enable monitor mode
    result = run_command(['airmon-ng', 'start', interface], sudo=True)
    if result:
        # Extract monitor interface name
        for line in result.split('\n'):
            if 'monitor mode' in line.lower():
                mon_iface = line.split()[1]
                return mon_iface
    return None

def disable_monitor_mode(interface):
    """Disable monitor mode"""
    print(f"{Fore.CYAN}[*] Disabling monitor mode on {interface}{Style.RESET_ALL}")
    run_command(['airmon-ng', 'stop', interface], sudo=True)