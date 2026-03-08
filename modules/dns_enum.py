import dns.resolver
from colorama import Fore, Style

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(target):
    print(f"\n{Fore.GREEN}[+] DNS Enumeration — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")

    found = False
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            for rdata in answers:
                print(f"  {Fore.CYAN}{rtype:<8}{Style.RESET_ALL} {rdata}")
                found = True
        except Exception:
            pass

    if not found:
        print(f"  {Fore.YELLOW}No records found.{Style.RESET_ALL}")
