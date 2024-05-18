import argparse
import socket
import ipaddress
import concurrent.futures
import re
import subprocess

print("""
      ____  _____                                 
    ____  / __ \/ ___/_________ _____  ____  ___  _____
   / __ \/ / / /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  / /_/ / /_/ /___/ / /__/ /_/ / / / / / / /  __/ /    
 / .___/\____//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
/_/    \n""")
print("Just a Sec!")
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
}

def scan(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)
                banner = get_banner(ip, port)
                return ip, port, service, banner
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
        return None

def get_service_name(port):
    return COMMON_SERVICES.get(port, "Unknown")

def get_banner(ip, port):
    try:
        cmd_output = subprocess.check_output(["timeout", "1", "nc", "-v", "-z", "-n", ip, str(port)], stderr=subprocess.STDOUT, timeout=5)
        banner = cmd_output.decode('utf-8').strip()
        return banner
    except Exception as e:
        print(f"Error getting banner for port {port} on {ip}: {e}")
        return "Banner not available"

def scan_ip(ip, ports, timeout):
    stored_results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = executor.map(lambda port: scan(ip, port, timeout), ports)
        stored_results.extend([result for result in results if result])
    return stored_results

def scan_cidr_range(cidr, ports, timeout):
    stored_results = []
    for ip_obj in ipaddress.IPv4Network(cidr):
        ip = str(ip_obj)
        stored_results.extend(scan_ip(ip, ports, timeout))
    return stored_results

def main():
    parser = argparse.ArgumentParser(description='Simple port scanner.')
    parser.add_argument('-T','--target', type=str, help='CIDR range or IP address to scan (e.g., 192.168.0.0/24 or 192.168.0.1)')
    parser.add_argument('-p', '--ports', type=str, default='1-1024', help='Port range to scan (default: 1-1024)')
    parser.add_argument('-t', '--timeout', type=float, default=0.5, help='Connection timeout in seconds (default: 0.5)')
    args = parser.parse_args()

    try:
        if '/' in args.target:  # Check if CIDR notation is used
            ipaddress.IPv4Network(args.target)
            target_type = 'CIDR'
        else:  # Otherwise, assume it's a single IP address
            ipaddress.IPv4Address(args.target)
            target_type = 'IP'
    except ValueError:
        print("Invalid target format. Please provide a valid CIDR range or IP address.")
        return

    p_range_pattern = re.compile(r'(\d+)-(\d+)')
    valida = p_range_pattern.search(args.ports.replace(" ", ""))
    if not valida:
        print("Invalid port range format. Please try again.")
        return
    min_p = int(valida.group(1))
    max_p = int(valida.group(2))
    ports = range(min_p, max_p + 1)

    if target_type == 'CIDR':
        stored_results = scan_cidr_range(args.target, ports, args.timeout)
    else:
        stored_results = scan_ip(args.target, ports, args.timeout)

    for ip, port, service, banner in stored_results:
        print(f"Port {port} ({service}) is open on {ip}. Banner: {banner}")

if __name__ == "__main__":
    main()
