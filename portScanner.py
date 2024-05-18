import argparse,socket,ipaddress,concurrent.futures,re,subprocess,logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BANNER = """
      ____  _____                                 
    ____  / __ \/ ___/_________ _____  ____  ___  _____
   / __ \/ / / /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  / /_/ / /_/ /___/ / /__/ /_/ / / / / / / /  __/ /    
 / .___/\____//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
/_/    
\n\nBy @Loki\n"""
logging.info(60 * "=")
logging.info("\n" + BANNER + "\n")
logging.info(60 * "=")
logging.info("Just a Sec!")

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
        logging.error(f"Error scanning port {port} on {ip}: {e}")
    return None

def get_service_name(port):
    return COMMON_SERVICES.get(port, "Unknown")

def get_banner(ip, port):
    try:
        result = subprocess.run(
            ["nc", "-v", "-z", "-n", ip, str(port)],
            capture_output=True, text=True, timeout=1
        )
        return result.stdout.strip() if result.returncode == 0 else "No banner"
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout expired when getting banner for port {port} on {ip}")
    except subprocess.SubprocessError as e:
        logging.error(f"Error getting banner for port {port} on {ip}: {e}")
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
        logging.info(f"Scanning IP: {ip}")
        stored_results.extend(scan_ip(ip, ports, timeout))
    return stored_results

def scan_target(target, ports, timeout):
    try:
        if '/' in target:
            ipaddress.IPv4Network(target)
            return scan_cidr_range(target, ports, timeout)
        else:
            ipaddress.IPv4Address(target)
            return scan_ip(target, ports, timeout)
    except ValueError:
        logging.error(f"Invalid target format: {target}")
        return []

def scan_multiple_targets(targets, ports, timeout):
    all_results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_target = {executor.submit(scan_target, target, ports, timeout): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                logging.error(f"Error scanning target {target}: {e}")
    return all_results

def parse_ports(port_range):
    try:
        start, end = map(int, port_range.split('-'))
        if start < 1 or end > 65535 or start > end:
            raise ValueError
        return range(start, end + 1)
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid port range. Please use the format 'start-end' within the range 1-65535.")

def main():
    parser = argparse.ArgumentParser(description='Simple port scanner.')
    parser.add_argument('-T', '--target', type=str, required=True, help='Comma-separated list of CIDR ranges or IP addresses to scan (e.g., 192.168.0.0/24,192.168.1.1)')
    parser.add_argument('-p', '--ports', type=parse_ports, default='1-1024', help='Port range to scan (default: 1-1024)')
    parser.add_argument('-t', '--timeout', type=float, default=0.5, help='Connection timeout in seconds (default: 0.5)')
    args = parser.parse_args()

    targets = args.target.split(',')
    ports = args.ports

    all_results = scan_multiple_targets(targets, ports, args.timeout)

    for ip, port, service, banner in all_results:
        logging.info(f"Port {port} ({service}) is open on {ip}.")

if __name__ == "__main__":
    main()