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
    family, address, port = args
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            endpoint = (address[0], port, *address[2:])
            result = sock.connect_ex(endpoint)
        return (address, port) if result == 0 else None
    except OSError:
        return None


def _resolve_target(target):
    addresses = socket.getaddrinfo(
        target, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    unique = []
    seen = set()
    for family, _, _, _, address in addresses:
        key = family, address
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def run(target):
    print(f"\n{Fore.GREEN}[+] Port Scan — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Scanning {len(COMMON_PORTS)} common ports...{Style.RESET_ALL}\n")

    try:
        addresses = _resolve_target(target)
    except socket.gaierror as e:
        print(f"  {Fore.RED}Could not resolve target: {e}{Style.RESET_ALL}")
        return

    if not addresses:
        print(f"  {Fore.RED}Target resolved to no usable addresses.{Style.RESET_ALL}")
        return

    print(
        f"  {Fore.CYAN}Resolved addresses:{Style.RESET_ALL} "
        + ", ".join(address[0] for _, address in addresses)
    )

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(
            executor.map(
                _scan_port,
                [
                    (family, address, port)
                    for family, address in addresses
                    for port in COMMON_PORTS
                ],
            )
        )

    open_by_address = {address: [] for _, address in addresses}
    for result in results:
        if result:
            address, port = result
            open_by_address[address].append(port)

    if not any(open_by_address.values()):
        print(f"  {Fore.YELLOW}No common ports open.{Style.RESET_ALL}")
        return

    for _, address in addresses:
        if not open_by_address[address]:
            continue
        print(f"\n  {Fore.CYAN}{address[0]}{Style.RESET_ALL}")
        for port in sorted(open_by_address[address]):
            service = COMMON_PORTS.get(port, "Unknown")
            print(
                f"  {Fore.GREEN}OPEN{Style.RESET_ALL}  {port:<8} "
                f"{Fore.CYAN}{service}{Style.RESET_ALL}"
            )
