import whois
from colorama import Fore, Style


def run(target):
    print(f"\n{Fore.GREEN}[+] WHOIS Lookup — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")

    try:
        w = whois.whois(target)
        fields = {
            "Registrar":    w.registrar,
            "Created":      w.creation_date,
            "Expires":      w.expiration_date,
            "Updated":      w.updated_date,
            "Name Servers": w.name_servers,
            "Org":          w.org,
            "Country":      w.country,
            "Emails":       w.emails,
        }
        for key, val in fields.items():
            if not val:
                continue
            if isinstance(val, list):
                val = val[0] if val else None
            if val:
                print(f"  {Fore.CYAN}{key:<14}{Style.RESET_ALL} {val}")
    except Exception as e:
        print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
