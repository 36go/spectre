import sys

from colorama import init, just_fix_windows_console

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stdout.isatty():
    just_fix_windows_console()
else:
    init(strip=True, convert=False)
