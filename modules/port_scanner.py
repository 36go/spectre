import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt2",
    27017: "MongoDB",
    9200:  "Elasticsearch",
}


def _scan_port(args):
    host, port = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        s.close()
        return port if result == 0 else None
    except Exception:
        return None


def run(target):
    print(f"\n{Fore.GREEN}[+] Port Scan — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Scanning {len(COMMON_PORTS)} common ports...{Style.RESET_ALL}\n")

    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        host = target

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(_scan_port, [(host, p) for p in COMMON_PORTS]))

    open_ports = [p for p in results if p]

    if open_ports:
        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"  {Fore.GREEN}OPEN{Style.RESET_ALL}  {port:<8} {Fore.CYAN}{service}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}No common ports open.{Style.RESET_ALL}")
