import argparse
import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

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
    print("Advanced Port Scanner - Phase 3 (Service Detection)")
    print("-" * 50)

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description="Educational Port Scanner with Service Detection")
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", help="Ports (e.g., 80,443 or 1-100)")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout (default: 1.0s)")
    parser.add_argument("-o", "--output", help="Save results to file (e.g., report.txt)")
    parser.add_argument("--banner", action="store_true", help="Try to grab service banners")
    return parser.parse_args()

def parse_ports(ports_str):
    if not ports_str:
        # پورت‌های معروف برای اسکن پیش‌فرض
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

def get_service_name(port):
    """تلاش برای پیدا کردن نام سرویس از روی شماره پورت"""
    common_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    return common_services.get(port, "Unknown")

def grab_banner(target, port, timeout):
    """
    تلاش برای دریافت Banner از سرویس
    مطابق مفهوم Fingerprinting در اسلاید 
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # برای برخی سرویس‌ها مثل HTTP می‌توانیم درخواست بفرستیم
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:
            sock.recv(1024)  # FTP معمولاً خودش banner می‌فرسته

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            # تمیز کردن banner برای نمایش
            banner = banner.replace('\n', ' ').replace('\r', '')[:50]
            return banner
        return "No Banner"
    except:
        return "N/A"

def scan_port(target, port, timeout, grab_banner_flag):
    """
    اسکن پورت + شناسایی سرویس
    """
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
                banner = grab_banner(target, port, timeout)
                sock.close()
                # اتصال مجدد برای banner ممکن است لازم باشد
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((target, port))
                    if port == 80 or port == 8080:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:50]
                    sock.close()
                except:
                    banner = "N/A"
            
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
            
    except socket.error as e:
        return {"port": port, "status": "FILTERED", "service": "", "banner": "", "response_time": ""}

def save_report(results, target, output_file):
    """ذخیره گزارش در فایل"""
    try:
        with open(output_file, 'w') as f:
            f.write("=" * 50 + "\n")
            f.write("PORT SCAN REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write("=" * 50 + "\n\n")
            
            for r in results:
                if r["status"] == "OPEN":
                    f.write(f"Port {r['port']:<5} | {r['service']:<15} | {r['banner']}\n")
            
            f.write("\n" + "=" * 50 + "\n")
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
        
    ports = parse_ports(args.ports)
    
    print(f"{Colors.YELLOW}[+] Target: {args.target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Ports: {len(ports)} ports to scan{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Threads: {args.threads}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Banner Grabbing: {'Enabled' if args.banner else 'Disabled'}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Start Time: {datetime.now()}{Colors.RESET}")
    print("-" * 50)
    
    open_ports = []
    results = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.target, port, args.timeout, args.banner): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            
            if result["status"] == "OPEN":
                open_ports.append(result)
                banner_info = f"({result['banner']})" if result['banner'] and result['banner'] != "N/A" else ""
                print(f"{Colors.GREEN}[+] Port {result['port']:<5} | {result['service']:<15} | {result['response_time']} {banner_info}{Colors.RESET}")

            else :
                print(f"{Colors.RED}[-] Port {result['port']:<5} is {result['status']}{Colors.RESET}")

            

    print("-" * 50)
    print(f"{Colors.GREEN}[✓] Scan Completed.{Colors.RESET}")
    print(f"{Colors.BLUE}[i] Total Open Ports Found: {len(open_ports)}{Colors.RESET}")
    
    if args.output:
        save_report(open_ports, args.target, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan Interrupted by User.{Colors.RESET}")
        sys.exit(0)