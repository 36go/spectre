import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from modules import http_analyzer, port_scanner, subdomain_enum


class SubdomainTests(unittest.TestCase):
    def test_wildcard_detection_combines_random_responses(self):
        with patch.object(
            subdomain_enum,
            "_resolve_addresses",
            side_effect=[frozenset({"192.0.2.1"}), frozenset({"192.0.2.2"})],
        ):
            addresses = subdomain_enum._detect_wildcard_addresses(
                "example.test", samples=2
            )
        self.assertEqual(addresses, {"192.0.2.1", "192.0.2.2"})

    def test_wildcard_match_is_not_probed(self):
        with (
            patch.object(
                subdomain_enum,
                "_resolve_addresses",
                return_value=frozenset({"192.0.2.1"}),
            ),
            patch.object(subdomain_enum.requests, "get") as request,
        ):
            result = subdomain_enum._check(
                ("www", "example.test", frozenset({"192.0.2.1"}))
            )
        self.assertTrue(result.wildcard)
        request.assert_not_called()

    def test_dns_discovery_survives_https_tls_failure(self):
        with (
            patch.object(
                subdomain_enum,
                "_resolve_addresses",
                return_value=frozenset({"192.0.2.10"}),
            ),
            patch.object(
                subdomain_enum.requests,
                "get",
                side_effect=requests.exceptions.SSLError,
            ),
        ):
            result = subdomain_enum._check(("api", "example.test", frozenset()))
        self.assertEqual(result.addresses, ("192.0.2.10",))
        self.assertEqual(result.error, "TLS verification failed")
        self.assertIsNone(result.status)

    def test_successful_https_probe_is_closed(self):
        response = Mock(status_code=204)
        with (
            patch.object(
                subdomain_enum,
                "_resolve_addresses",
                return_value=frozenset({"192.0.2.10"}),
            ),
            patch.object(subdomain_enum.requests, "get", return_value=response),
        ):
            result = subdomain_enum._check(("api", "example.test", frozenset()))
        self.assertEqual(result.status, 204)
        response.close.assert_called_once_with()


class SecurityHeaderTests(unittest.TestCase):
    def assert_valid(self, name, value, is_https=True):
        valid, reason = http_analyzer._validate_security_header(
            name, value, is_https
        )
        self.assertTrue(valid, reason)

    def assert_invalid(self, name, value, is_https=True):
        valid, _ = http_analyzer._validate_security_header(name, value, is_https)
        self.assertFalse(valid)

    def test_security_header_values(self):
        self.assert_valid("Strict-Transport-Security", "max-age=31536000")
        self.assert_invalid("Strict-Transport-Security", "max-age=0")
        self.assert_valid("Content-Security-Policy", "default-src 'self'")
        self.assert_invalid("Content-Security-Policy", "report-uri /csp")
        self.assert_invalid("Content-Security-Policy", "default-src *")
        self.assert_valid("X-Frame-Options", "DENY")
        self.assert_invalid("X-Frame-Options", "ALLOWALL")
        self.assert_valid("X-Content-Type-Options", "nosniff")
        self.assert_invalid("X-Content-Type-Options", "sniff")
        self.assert_valid("Referrer-Policy", "strict-origin-when-cross-origin")
        self.assert_invalid("Referrer-Policy", "unsafe-url")
        self.assert_valid("Permissions-Policy", "camera=(), geolocation=(self)")
        self.assert_invalid("Permissions-Policy", "camera=*")

    def test_hsts_rejects_duplicate_and_malformed_directives(self):
        self.assert_valid(
            "Strict-Transport-Security",
            'max-age="31536000"; includeSubDomains; preload;',
        )
        self.assert_invalid(
            "Strict-Transport-Security", "max-age=10; MAX-AGE=20"
        )
        self.assert_invalid("Strict-Transport-Security", "max-age=10;; preload")
        self.assert_invalid(
            "Strict-Transport-Security", "max-age=10 garbage"
        )
        self.assert_invalid("Strict-Transport-Security", "max-age==10")
        self.assert_invalid(
            "Strict-Transport-Security", "max-age=10; includeSubDomains=true"
        )

    def test_csp_requires_semantically_restrictive_directives(self):
        self.assert_valid("Content-Security-Policy", "frame-ancestors 'self'")
        self.assert_valid("Content-Security-Policy", "object-src 'none'")
        self.assert_valid("Content-Security-Policy", "sandbox")
        self.assert_valid(
            "Content-Security-Policy",
            "script-src 'nonce-value' 'strict-dynamic' https:",
        )
        self.assert_invalid("Content-Security-Policy", "frame-ancestors *")
        self.assert_invalid("Content-Security-Policy", "frame-ancestors")
        self.assert_invalid("Content-Security-Policy", "default-src")
        self.assert_invalid("Content-Security-Policy", "default-src https:")
        self.assert_invalid(
            "Content-Security-Policy", "script-src * 'unsafe-inline'"
        )
        self.assert_invalid(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors *",
        )
        self.assert_invalid("Content-Security-Policy", "report-uri /csp")
        self.assert_invalid(
            "Content-Security-Policy", "default-src 'self'; DEFAULT-SRC 'none'"
        )

    def test_hsts_is_not_applicable_to_http(self):
        valid, reason = http_analyzer._validate_security_header(
            "Strict-Transport-Security", "max-age=31536000", is_https=False
        )
        self.assertIsNone(valid)
        self.assertIn("ignored", reason)


class PortScannerTests(unittest.TestCase):
    def test_all_unique_resolved_addresses_are_returned(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        with patch.object(socket, "getaddrinfo", return_value=answers):
            addresses = port_scanner._resolve_target("example.test")
        self.assertEqual(len(addresses), 2)
        self.assertEqual({address[1][0] for address in addresses}, {"192.0.2.1", "2001:db8::1"})

    def test_localhost_open_port_check(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            result = port_scanner._scan_port(
                (socket.AF_INET, ("127.0.0.1", 0), port)
            )
        self.assertEqual(result, (("127.0.0.1", 0), port))

    def test_run_scans_every_resolved_address(self):
        addresses = [
            (socket.AF_INET, ("192.0.2.1", 0)),
            (socket.AF_INET6, ("2001:db8::1", 0, 0, 0)),
        ]
        with (
            patch.object(port_scanner, "_resolve_target", return_value=addresses),
            patch.object(port_scanner, "_scan_port", return_value=None) as scan,
            patch("builtins.print"),
        ):
            port_scanner.run("example.test")
        self.assertEqual(scan.call_count, len(addresses) * len(port_scanner.COMMON_PORTS))


class OutputTests(unittest.TestCase):
    def test_redirected_cli_output_has_no_ansi_sequences(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "spectre.py", "scan", "localhost"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"\x1b[", result.stdout)
        self.assertNotIn(b"\x1b[", result.stderr)


if __name__ == "__main__":
    unittest.main()
