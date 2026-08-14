![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![For authorized use only](https://img.shields.io/badge/⚠%20Authorized%20Use-Only-red?style=flat-square)

# spectre

Web reconnaissance tool by [expect-us](https://github.com/hz8n/expect-us)

> **⚠ WARNING — For authorized targets only.**
> Using this tool against systems you do not own or have explicit written permission to test is **illegal**.
> The authors are not responsible for any misuse.
> This tool is intended for **security research**, **CTF competitions**, and **authorized penetration testing only**.

---

## Features

| Module | Description |
|--------|-------------|
| `--dns` | DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `--whois` | WHOIS lookup (registrar, dates, name servers, org) |
| `--http` | HTTP headers analysis + security header value audit |
| `--ports` | Common port scan across all resolved addresses |
| `--subs` | DNS-first subdomain enumeration with wildcard filtering and HTTPS probes |
| `--all` | Run all modules |

---

## Installation

```bash
git clone https://github.com/hz8n/spectre.git
cd spectre
python -m pip install -r requirements.txt
```

---

## Usage

```bash
# Run all modules
python spectre.py scan example.com --all

# DNS + HTTP only
python spectre.py scan example.com --dns --http

# Port scan
python spectre.py scan example.com --ports

# Subdomain enumeration
python spectre.py scan example.com --subs

# Help
python spectre.py scan --help
```

---

## Example Output

```
[+] DNS Enumeration — example.com
────────────────────────────────────────────────────
  A        93.184.216.34
  NS       a.iana-servers.net.
  MX       0 .

[+] HTTP Analysis — example.com
────────────────────────────────────────────────────
  Status               200
  Final URL            https://example.com/

  Security Headers:
  ✓ Strict-Transport-Security
  ✗ Content-Security-Policy (missing)
  ✗ X-Frame-Options (missing)

[+] Port Scan — example.com
────────────────────────────────────────────────────
  OPEN   80       HTTP
  OPEN   443      HTTPS
```

---

## Project Structure

```
spectre/
├── spectre.py              # CLI entry point
└── modules/
    ├── dns_enum.py         # DNS record enumeration
    ├── whois_lookup.py     # WHOIS lookup
    ├── http_analyzer.py    # HTTP headers + security audit
    ├── port_scanner.py     # Multithreaded port scanner
    └── subdomain_enum.py   # Subdomain enumeration
```

Subdomain results distinguish DNS discovery from HTTPS availability. Random
nonexistent labels are resolved first; candidates matching wildcard DNS answers
are reported and excluded from the discovery total.

## Tests

The test suite uses mocks and loopback sockets only:

```bash
python -m unittest discover -s tests -v
```

---

## Legal

This tool is released under the MIT License for **educational and authorized security testing purposes only**.

---
---

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![للاستخدام المصرح به فقط](https://img.shields.io/badge/⚠%20استخدام%20مصرح-فقط-red?style=flat-square)

# spectre — بالعربي

أداة استطلاع ويب من [expect-us](https://github.com/hz8n/expect-us)

> **⚠ تحذير — للاستخدام على الأهداف المصرح بها فقط.**
> استخدام هذه الأداة على أنظمة لا تملكها أو لم تحصل على إذن كتابي صريح لاختبارها **مخالف للقانون**.
> المطورون غير مسؤولين عن أي إساءة في الاستخدام.
> هذه الأداة مخصصة لـ **أبحاث الأمن** و **مسابقات CTF** و **اختبار الاختراق المصرح به فقط**.

---

## المميزات

| الوحدة | الوصف |
|--------|-------|
| `--dns` | استعراض سجلات DNS |
| `--whois` | معلومات WHOIS للدومين |
| `--http` | تحليل HTTP headers وفحص Security headers |
| `--ports` | فحص المنافذ الشائعة |
| `--subs` | البحث عن الـ subdomains |
| `--all` | تشغيل جميع الوحدات |

---

## التثبيت

```bash
git clone https://github.com/hz8n/spectre.git
cd spectre
python -m pip install -r requirements.txt
```

---

## الاستخدام

```bash
# تشغيل كل الوحدات
python spectre.py scan example.com --all

# DNS و HTTP فقط
python spectre.py scan example.com --dns --http

# فحص المنافذ
python spectre.py scan example.com --ports
```

---

## الترخيص

MIT — للأغراض التعليمية واختبار الاختراق المصرح به فقط.
