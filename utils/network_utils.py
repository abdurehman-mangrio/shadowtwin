#!/usr/bin/env python3
"""
Network utility functions for ShadowTwin
"""

import subprocess
import re
from colorama import Fore, Style

def get_interface_mode(interface):
    """Get current mode of wireless interface"""
    try:
        result = subprocess.run(['iwconfig', interface], 
                              capture_output=True, text=True, check=True)
        
        if 'Mode:Monitor' in result.stdout:
            return 'monitor'
        elif 'Mode:Managed' in result.stdout:
            return 'managed'
        else:
            return 'unknown'
    except subprocess.CalledProcessError:
        return 'error'

def get_interface_channel(interface):
    """Get current channel of wireless interface"""
    try:
        result = subprocess.run(['iwconfig', interface], 
                              capture_output=True, text=True, check=True)
        
        channel_match = re.search(r'Frequency:(\d+\.\d+) GHz.*Channel (\d+)', result.stdout)
        if channel_match:
            return int(channel_match.group(2))
        return None
    except subprocess.CalledProcessError:
        return None

def check_wireless_tools():
    """Check if required wireless tools are available"""
    tools = ['iwconfig', 'iwlist', 'ifconfig', 'airmon-ng', 'airodump-ng']
    missing = []
    
    for tool in tools:
        try:
            subprocess.run(['which', tool], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            missing.append(tool)
    
    return missing

def get_network_info():
    """Get comprehensive network information"""
    try:
        # Get routing table
        result = subprocess.run(['route', '-n'], capture_output=True, text=True)
        print(f"{Fore.CYAN}Routing Table:{Style.RESET_ALL}")
        print(result.stdout)
        
        # Get wireless interfaces
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        print(f"{Fore.CYAN}Wireless Interfaces:{Style.RESET_ALL}")
        print(result.stdout)
        
    except Exception as e:
        print(f"{Fore.RED}Error getting network info: {e}{Style.RESET_ALL}")