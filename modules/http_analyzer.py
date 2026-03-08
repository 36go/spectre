import requests
from colorama import Fore, Style

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

INFO_HEADERS = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]


def run(target):
    print(f"\n{Fore.GREEN}[+] HTTP Analysis — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")

    url = target if target.startswith("http") else f"https://{target}"

    try:
        r = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; spectre/1.0)"},
            verify=False,
        )

        print(f"  {Fore.CYAN}{'Status':<20}{Style.RESET_ALL} {r.status_code}")
        print(f"  {Fore.CYAN}{'Final URL':<20}{Style.RESET_ALL} {r.url}")

        # Info-leaking headers
        print(f"\n  {Fore.WHITE}Server Info:{Style.RESET_ALL}")
        leaked = False
        for h in INFO_HEADERS:
            if h in r.headers:
                print(f"  {Fore.YELLOW}  ⚠ {h:<18}{Style.RESET_ALL} {r.headers[h]}")
                leaked = True
        if not leaked:
            print(f"  {Fore.GREEN}  ✓ No info-leaking headers found.{Style.RESET_ALL}")

        # Security headers
        print(f"\n  {Fore.WHITE}Security Headers:{Style.RESET_ALL}")
        for h in SECURITY_HEADERS:
            if h in r.headers:
                print(f"  {Fore.GREEN}  ✓ {h}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}  ✗ {h} (missing){Style.RESET_ALL}")

    except requests.exceptions.SSLError:
        print(f"  {Fore.RED}SSL certificate error.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"  {Fore.RED}Connection failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
