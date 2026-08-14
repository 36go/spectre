import secrets
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests
from colorama import Fore, Style

WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "ns4",
    "vpn", "mx", "relay", "test", "dev", "staging", "api", "admin", "portal",
    "remote", "blog", "cdn", "static", "assets", "media", "upload", "store",
    "shop", "cpanel", "whm", "autodiscover", "autoconfig", "support", "status",
    "help", "docs", "wiki", "forum", "beta", "alpha", "demo", "app", "m",
    "mobile", "dashboard", "panel", "monitor", "git", "gitlab", "github",
    "jenkins", "jira", "confluence", "grafana", "kibana", "elk", "vault",
    "login", "auth", "sso", "id", "account", "accounts", "secure", "security",
    "old", "new", "backup", "bkp", "db", "database", "internal", "intranet",
    "extranet", "dev2", "stage", "uat", "qa", "prod", "production",
]


@dataclass(frozen=True)
class ProbeResult:
    subdomain: str
    addresses: tuple[str, ...]
    status: int | None = None
    error: str | None = None
    wildcard: bool = False


def _resolve_addresses(host):
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return frozenset()
    return frozenset(answer[4][0] for answer in answers)


def _detect_wildcard_addresses(domain, samples=3):
    addresses = set()
    for _ in range(samples):
        label = f"spectre-{secrets.token_hex(8)}"
        addresses.update(_resolve_addresses(f"{label}.{domain}"))
    return frozenset(addresses)


def _check(args):
    sub, domain, wildcard_addresses = args
    host = f"{sub}.{domain}"
    addresses = _resolve_addresses(host)
    if not addresses:
        return None
    sorted_addresses = tuple(sorted(addresses))
    if wildcard_addresses and addresses.issubset(wildcard_addresses):
        return ProbeResult(sub, sorted_addresses, wildcard=True)

    try:
        response = requests.get(
            f"https://{host}",
            timeout=(3, 4),
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; spectre/1.0)"},
        )
        try:
            return ProbeResult(sub, sorted_addresses, status=response.status_code)
        finally:
            response.close()
    except requests.exceptions.SSLError:
        return ProbeResult(sub, sorted_addresses, error="TLS verification failed")
    except requests.exceptions.Timeout:
        return ProbeResult(sub, sorted_addresses, error="HTTPS timed out")
    except requests.exceptions.ConnectionError:
        return ProbeResult(sub, sorted_addresses, error="HTTPS connection failed")
    except requests.exceptions.RequestException:
        return ProbeResult(sub, sorted_addresses, error="HTTPS probe failed")


def run(target):
    print(f"\n{Fore.GREEN}[+] Subdomain Enumeration — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Checking {len(WORDLIST)} subdomains...{Style.RESET_ALL}\n")

    wildcard_addresses = _detect_wildcard_addresses(target)
    if wildcard_addresses:
        print(
            f"  {Fore.YELLOW}Wildcard DNS detected; matching candidates will be "
            f"excluded.{Style.RESET_ALL}\n"
        )

    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(
            executor.map(
                _check,
                [(sub, target, wildcard_addresses) for sub in WORDLIST],
            )
        )

    found = []
    wildcard_matches = 0
    for result in results:
        if result is None:
            continue
        host = f"{result.subdomain}.{target}"
        addresses = ", ".join(result.addresses)
        if result.wildcard:
            wildcard_matches += 1
            print(f"  {Fore.YELLOW}[WILDCARD]{Style.RESET_ALL} {host} -> {addresses}")
            continue

        found.append(result.subdomain)
        if result.status is not None:
            color = Fore.GREEN if result.status < 400 else Fore.YELLOW
            print(
                f"  {Fore.CYAN}[DNS]{Style.RESET_ALL} {host} -> {addresses}  "
                f"{color}[HTTPS {result.status}]{Style.RESET_ALL}"
            )
        else:
            print(
                f"  {Fore.CYAN}[DNS]{Style.RESET_ALL} {host} -> {addresses}  "
                f"{Fore.YELLOW}[{result.error}]{Style.RESET_ALL}"
            )

    if found:
        print(f"\n  {Fore.GREEN}DNS-discovered {len(found)} subdomain(s).{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}No non-wildcard subdomains found.{Style.RESET_ALL}")
    if wildcard_matches:
        print(f"  {Fore.YELLOW}Excluded {wildcard_matches} wildcard match(es).{Style.RESET_ALL}")
