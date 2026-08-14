import re
from urllib.parse import urlsplit

import requests
from colorama import Fore, Style

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_HEADERS = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]

_HSTS_DIRECTIVE = re.compile(
    r"^([a-z][a-z0-9-]*)(?:\s*=\s*(\"[^\"]*\"|[!#$%&'*+\-.^_`|~a-z0-9]+))?$",
    re.IGNORECASE,
)
_CSP_DIRECTIVE_NAME = re.compile(r"^[a-z][a-z0-9-]*$", re.IGNORECASE)


def _validate_hsts(value):
    directives = {}
    parts = value.split(";")
    for index, part in enumerate(parts):
        part = part.strip()
        if not part:
            if index == len(parts) - 1:
                continue
            return False, "empty directive"
        match = _HSTS_DIRECTIVE.fullmatch(part)
        if not match:
            return False, "malformed directive"
        name = match.group(1).lower()
        if name in directives:
            return False, f"duplicate {name} directive"
        directives[name] = match.group(2)

    max_age = directives.get("max-age")
    if max_age is None:
        return False, "max-age is required"
    max_age = max_age.strip('"')
    if not max_age.isdigit() or int(max_age) <= 0:
        return False, "max-age must be a positive integer"
    for flag in ("includesubdomains", "preload"):
        if directives.get(flag) is not None:
            return False, f"{flag} must not have a value"
    return True, None


def _parse_csp(value):
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not _CSP_DIRECTIVE_NAME.fullmatch(name):
            return None, "malformed directive name"
        if name in directives:
            return None, f"duplicate {name} directive"
        directives[name] = tuple(token.lower() for token in tokens[1:])
    return directives, None


def _restrictive_source_list(name, sources):
    if not sources:
        return False
    if name == "script-src" and "'strict-dynamic'" in sources and any(
        source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
        for source in sources
    ):
        return True

    permissive = {
        "*",
        "http:",
        "https:",
        "data:",
        "blob:",
        "filesystem:",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "'wasm-unsafe-eval'",
    }
    if any(source in permissive for source in sources):
        return False
    if "'none'" in sources:
        return len(sources) == 1
    return True


def _validate_csp(value):
    directives, error = _parse_csp(value)
    if error:
        return False, error

    effective = False
    source_directives = {
        "default-src",
        "script-src",
        "script-src-elem",
        "object-src",
        "frame-ancestors",
    }
    for name in source_directives.intersection(directives):
        if not _restrictive_source_list(name, directives[name]):
            return False, f"{name} is empty or permissive"
        effective = True

    if "sandbox" in directives:
        effective = True
    for name in ("upgrade-insecure-requests", "block-all-mixed-content"):
        if name in directives:
            if directives[name]:
                return False, f"{name} must not have a value"
            effective = True
    if not effective:
        return False, "no semantically restrictive directive"
    return True, None


def _validate_security_header(name, value, is_https=True):
    value = value.strip()
    if not value:
        return False, "empty value"

    if name == "Strict-Transport-Security":
        if not is_https:
            return None, "ignored on non-HTTPS responses"
        return _validate_hsts(value)
    elif name == "Content-Security-Policy":
        return _validate_csp(value)
    elif name == "X-Frame-Options":
        if value.upper() not in {"DENY", "SAMEORIGIN"}:
            return False, "expected DENY or SAMEORIGIN"
    elif name == "X-Content-Type-Options":
        if value.lower() != "nosniff":
            return False, "expected nosniff"
    elif name == "Referrer-Policy":
        effective = value.split(",")[-1].strip().lower()
        secure_policies = {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }
        if effective not in secure_policies:
            return False, "effective policy is missing or permissive"
    elif name == "Permissions-Policy":
        restrictive_feature = re.search(
            r"(?:^|,)\s*[a-z][a-z0-9-]*\s*=\s*\(\s*(?:self)?\s*\)",
            value,
            re.IGNORECASE,
        )
        if not restrictive_feature:
            return False, "no feature is restricted to self or none"
    return True, None


def run(target):
    print(f"\n{Fore.GREEN}[+] HTTP Analysis — {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'─' * 52}{Style.RESET_ALL}")

    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    if "://" in target and scheme not in {"http", "https"}:
        print(f"  {Fore.RED}Unsupported URL scheme: {parsed.scheme}{Style.RESET_ALL}")
        return

    url = target if scheme in {"http", "https"} else f"https://{target}"

    try:
        r = requests.get(
            url,
            timeout=(5, 10),
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; spectre/1.0)"},
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
        is_https = urlsplit(r.url).scheme.lower() == "https"
        for h in SECURITY_HEADERS:
            if h == "Strict-Transport-Security" and not is_https:
                print(
                    f"  {Fore.YELLOW}  ! {h} "
                    f"(ignored on non-HTTPS responses){Style.RESET_ALL}"
                )
                continue
            value = r.headers.get(h)
            if value is None:
                print(f"  {Fore.RED}  ✗ {h} (missing){Style.RESET_ALL}")
                continue
            valid, reason = _validate_security_header(h, value, is_https)
            if valid is True:
                print(f"  {Fore.GREEN}  ✓ {h}{Style.RESET_ALL}")
            elif valid is None:
                print(f"  {Fore.YELLOW}  ! {h} ({reason}){Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}  ✗ {h} (invalid: {reason}){Style.RESET_ALL}")

    except requests.exceptions.SSLError as e:
        print(f"  {Fore.RED}TLS certificate verification failed: {e}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
