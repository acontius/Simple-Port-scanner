import argparse
import socket
import sys
from datetime import datetime

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'

def banner():
    print(f"{Colors.GREEN}")
    print(r"""
    |\    | 0  -------    -------      /\
    | \   | | |      |   |      |     /  \
    |  \  | | |    ___   |    ___    /    \
    |   \ | | |       |  |       |  /------\
    |    \| | |_______|  |_______| /        \
    """)
    print(f"{Colors.RESET}")
    print("Simple Port Scanner")
    print("-" * 50)

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A simple CLI port scanner like Nmap"
    )
    parser.add_argument(
        "-t", "--target", 
        required=True, 
        help="Target IP address (e.g., 192.168.1.1)"
    )
    parser.add_argument(
        "-p", "--ports", 
        required=False, 
        help="Port range (e.g., 80 or 1-100 or 80,443,8080)"
    )
    
    args = parser.parse_args()
    
    if not validate_ip(args.target):
        print(f"{Colors.RED}[!] Invalid IP Address.{Colors.RESET}")
        sys.exit(1)
        
    return args

def parse_ports(ports_str):
    if not ports_str:
        # اگر پورتی مشخص نشد، پیش‌فرض اسکن پورت‌های معروف
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080]
    
    ports = []
    try:
        for part in ports_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
    except ValueError:
        print(f"{Colors.RED}[!] Invalid Port Format.{Colors.RESET}")
        sys.exit(1)
        
    return sorted(list(set(ports)))

def main():
    banner()
    
    # دریافت آرگومان‌ها
    args = parse_arguments()
    target = args.target
    ports = parse_ports(args.ports)
    
    print(f"{Colors.YELLOW}[+] Target: {target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Ports to scan: {len(ports)} ports{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Start Time: {datetime.now()}{Colors.RESET}")
    print("-" * 50)
    
    # اینجا محل قرارگیری منطق اسکن در فاز بعدی خواهد بود
    print(f"{Colors.GREEN}[✓] Structure Ready. Waiting for Scan Logic (Phase 2)...{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan Interrupted by User.{Colors.RESET}")
        sys.exit(0)