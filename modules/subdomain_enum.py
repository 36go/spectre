import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def _check(args):
    sub, domain = args
    url = f"https://{sub}.{domain}"
    try:
        r = requests.get(
            url,
            timeout=4,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; spectre/1.0)"},
        )
        return (sub, r.status_code, r.url)
    except Exception:
        return None


def run(target):
    print(f"\n{Fore.GREEN}[+] Subdomain Enumeration — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Checking {len(WORDLIST)} subdomains...{Style.RESET_ALL}\n")

    found = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(_check, [(s, target) for s in WORDLIST]))

    for result in results:
        if result:
            sub, status, url = result
            color = Fore.GREEN if status < 400 else Fore.YELLOW
            print(f"  {color}[{status}]{Style.RESET_ALL}  {sub}.{target}")
            found.append(sub)

    print(
        f"\n  {Fore.GREEN}Found {len(found)} subdomain(s).{Style.RESET_ALL}"
        if found else
        f"\n  {Fore.YELLOW}No subdomains found.{Style.RESET_ALL}"
    )
