import argparse
import socket
import sys
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def banner():
    """
    بنر اختصاصی ACONTIUS
    جایگزین بنر قبلی برای حفظ احترام و اخلاق حرفه‌ای
    """
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"""
        AA       CCCCC   OOO    N   N  TTTTT  III  U   U  SSSSS  
       A  A      C       O   O  NN  N    T     I   U   U  S         
      A    A     C       O   O  N N N    T     I   U   U  SSSSS     
     AAAAAAAA    C       O   O  N  NN    T     I   U   U      S     
    A        A   CCCCC   OOO    N   N    T    III   UUU   SSSSS     
    """)
    print(f"{Colors.RESET}")
    print("Advanced Educational Port Scanner")
    print("Based on Lec8 - Reconnaissance & Scanning")
    print("-" * 60)

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def check_host_alive(target):
    """
    بررسی زنده بودن هدف (Host Discovery)
    مطابق اسلاید ۱۸ (ICMP Method)
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.returncode == 0
    except Exception:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description="acontius - Educational Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", help="Ports (e.g., 80,443 or 1-100)")
    parser.add_argument("--threads", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout (default: 1.0s)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--banner", action="store_true", help="Try to grab service banners")
    parser.add_argument("--no-ping", action="store_true", help="Skip host discovery ping")
    return parser.parse_args()

def parse_ports(ports_str):
    if not ports_str:
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080, 445, 139]
    
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

def get_service_name(port):
    common_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        445: "SMB", 139: "NetBIOS"
    }
    return common_services.get(port, "Unknown")

def guess_os(open_ports):
    """
    تشخیص حدسی سیستم عامل بر اساس پورت‌های باز
    مرتبط با مفاهیم اسلاید ۲۸ (OS Detection)
    """
    os_hints = []
    if 445 in open_ports or 139 in open_ports or 3389 in open_ports:
        os_hints.append("Windows")
    if 22 in open_ports and 445 not in open_ports:
        os_hints.append("Linux/Unix")
    if 80 in open_ports or 443 in open_ports:
        os_hints.append("Web Server")
    
    if not os_hints:
        return "Unknown"
    return "/".join(list(set(os_hints)))

def grab_banner(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            banner = banner.replace('\n', ' ').replace('\r', '')[:60]
            return banner
        return "No Banner"
    except:
        return "N/A"

def scan_port(target, port, timeout, grab_banner_flag):
    start_time = datetime.now()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        
        if result == 0:
            service = get_service_name(port)
            banner = ""
            
            if grab_banner_flag:
                sock.close()
                banner = grab_banner(target, port, timeout)
            
            return {
                "port": port, 
                "status": "OPEN", 
                "service": service,
                "banner": banner,
                "response_time": f"{response_time:.3f}s"
            }
        else:
            sock.close()
            return {"port": port, "status": "CLOSED", "service": "", "banner": "", "response_time": ""}
            
    except socket.error:
        return {"port": port, "status": "FILTERED", "service": "", "banner": "", "response_time": ""}

def save_report(results, target, output_file, os_guess):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("ACONTIUS SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"OS Guess: {os_guess}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")
            
            for r in results:
                if r["status"] == "OPEN":
                    f.write(f"Port {r['port']:<5} | {r['service']:<15} | {r['banner']}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write(f"Total Open Ports: {len(results)}\n")
        print(f"{Colors.GREEN}[✓] Report saved to {output_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving report: {e}{Colors.RESET}")

def main():
    banner()
    args = parse_arguments()
    
    if not validate_ip(args.target):
        print(f"{Colors.RED}[!] Invalid IP Address.{Colors.RESET}")
        sys.exit(1)
    
    if not args.no_ping:
        print(f"{Colors.YELLOW}[+] Checking host availability (Ping)...{Colors.RESET}")
        if not check_host_alive(args.target):
            print(f"{Colors.RED}[!] Host {args.target} seems to be DOWN or blocking ICMP.{Colors.RESET}")
            choice = input("Continue anyway? (y/n): ").lower()
            if choice != 'y':
                sys.exit(0)
        else:
            print(f"{Colors.GREEN}[✓] Host is UP.{Colors.RESET}")
    
    ports = parse_ports(args.ports)
    
    print(f"{Colors.YELLOW}[+] Target: {args.target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Ports: {len(ports)} ports to scan{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Threads: {args.threads}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Start Time: {datetime.now()}{Colors.RESET}")
    print("-" * 60)
    
    open_ports = []
    results = []
    open_port_numbers = []
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, args.target, port, args.timeout, args.banner): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if result["status"] == "OPEN":
                    open_ports.append(result)
                    open_port_numbers.append(result["port"])
                    banner_info = f"({result['banner']})" if result['banner'] and result['banner'] != "N/A" else ""
                    print(f"{Colors.GREEN}[+] Port {result['port']:<5} | {result['service']:<15} | {result['response_time']} {banner_info}{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan Interrupted by User.{Colors.RESET}")
        sys.exit(0)

    os_guess = guess_os(open_port_numbers)
    
    print("-" * 60)
    print(f"{Colors.GREEN}[✓] Scan Completed.{Colors.RESET}")
    print(f"{Colors.BLUE}[i] Total Open Ports Found: {len(open_ports)}{Colors.RESET}")
    print(f"{Colors.BLUE}[i] Probable OS: {os_guess}{Colors.RESET}")
    
    if args.output:
        save_report(open_ports, args.target, args.output, os_guess)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Colors.RED}[!] Critical Error: {e}{Colors.RESET}")
        sys.exit(1)