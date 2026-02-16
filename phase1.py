import argparse
import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

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
    print("Simple Port Scanner - Phase 2 (TCP Connect Scanning)")
    print("-" * 50)

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description="Educational Port Scanner (TCP Connect)")
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", help="Ports (e.g., 80,443 or 1-100)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout (default: 1.0s)")
    return parser.parse_args()

def parse_ports(ports_str):
    if not ports_str:
        return [21, 22, 80, 443, 8080]
    
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

def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # connect_ex برگشت می‌دهد: 0 اگر موفق باشد، کد خطا اگر شکست بخورد
        result = sock.connect_ex((target, port))
        
        if result == 0:
            return {"port": port, "status": "OPEN", "service": "Unknown"}
        else:
            return {"port": port, "status": "CLOSED", "service": ""}
            
    except socket.error:
        return {"port": port, "status": "FILTERED", "service": ""}
    finally:
        sock.close()

def main():
    banner()
    args = parse_arguments()
    
    if not validate_ip(args.target):
        print(f"{Colors.RED}[!] Invalid IP Address.{Colors.RESET}")
        sys.exit(1)
        
    ports = parse_ports(args.ports)
    
    print(f"{Colors.YELLOW}[+] Target: {args.target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Ports: {len(ports)} ports to scan{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Threads: {args.threads}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Timeout: {args.timeout}s{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Start Time: {datetime.now()}{Colors.RESET}")
    print("-" * 50)
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.target, port, args.timeout): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result["status"] == "OPEN":
                open_ports.append(result["port"])
                print(f"{Colors.GREEN}[+] Port {result['port']:<5} is OPEN{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Port {result['port']:<5} is {result['status']}{Colors.RESET}")

    print("-" * 50)
    print(f"{Colors.GREEN}[✓] Scan Completed.{Colors.RESET}")
    print(f"{Colors.BLUE}[i] Total Open Ports Found: {len(open_ports)}{Colors.RESET}")
    if open_ports:
        print(f"{Colors.BLUE}[i] Open Ports List: {open_ports}{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan Interrupted by User.{Colors.RESET}")
        sys.exit(0)