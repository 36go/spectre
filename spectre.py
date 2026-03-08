#!/usr/bin/env python3
"""
spectre — web recon tool
by expect-us | For authorized targets only.
"""

import click
import sys
from colorama import Fore, Style, init
from modules import dns_enum, whois_lookup, http_analyzer, port_scanner, subdomain_enum

init(autoreset=True)

BANNER = f"""
{Fore.GREEN}
  ___ _ __   ___  ___| |_ _ __ ___
 / __| '_ \\ / _ \\/ __| __| '__/ _ \\
 \\__ \\ |_) |  __/ (__| |_| | |  __/
 |___/ .__/ \\___|\\___|\\__|_|  \\___|
     |_|
{Style.RESET_ALL}{Fore.RED}  ⚠  Authorized targets only. Unauthorized use is illegal.
{Style.RESET_ALL}{Fore.WHITE}  Web Recon Tool — github.com/hz8n/spectre
{Style.RESET_ALL}"""


@click.group()
def cli():
    """spectre — web reconnaissance tool by expect-us"""
    print(BANNER)


@cli.command()
@click.argument("target")
@click.option("--all", "run_all", is_flag=True, help="Run all modules")
@click.option("--dns",   is_flag=True, help="DNS record enumeration")
@click.option("--whois", is_flag=True, help="WHOIS lookup")
@click.option("--http",  is_flag=True, help="HTTP headers + security headers audit")
@click.option("--ports", is_flag=True, help="Common port scan")
@click.option("--subs",  is_flag=True, help="Subdomain enumeration")
def scan(target, run_all, dns, whois, http, ports, subs):
    """Scan a target domain or IP.

    \b
    Examples:
      spectre scan example.com --all
      spectre scan example.com --dns --http
      spectre scan 192.168.1.1 --ports
    """
    if not any([run_all, dns, whois, http, ports, subs]):
        click.echo(
            f"{Fore.YELLOW}[!] No module selected. Use --all or pick one. "
            f"Run 'spectre scan --help' for options.{Style.RESET_ALL}"
        )
        sys.exit(1)

    if run_all or dns:
        dns_enum.run(target)
    if run_all or whois:
        whois_lookup.run(target)
    if run_all or http:
        http_analyzer.run(target)
    if run_all or ports:
        port_scanner.run(target)
    if run_all or subs:
        subdomain_enum.run(target)

    print(f"\n{Fore.GREEN}[✓] Scan complete.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    cli()
