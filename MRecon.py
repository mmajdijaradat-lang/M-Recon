#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M-Recon v15.16
Protocol-aware reconnaissance scanner for authorized security testing.

Focus:
- IPv4 + IPv6 TCP scanning
- Optional TCP SYN state probes (Scapy; lazy-loaded, auto-fallback)
- Optional UDP probes with explicit states
- Adaptive timeouts + bounded concurrency + rate limiting
- Protocol-aware service/version fingerprinting via a modular probe registry
  (SSH, HTTP/HTTPS, FTP/SMTP/POP3/IMAP, MySQL, Redis, Memcached, PostgreSQL,
  MongoDB, AMQP/RabbitMQ, VNC, RDP -- add more with one probe method + one
  registry.register() call, no scanner dispatch changes needed)
- HTTP + real TLS handshake on any TCP port, with correct SNI handling for
  IPv4/IPv6/bracketed-IPv6 literals (SNI is only ever sent for real hostnames)
- WAF/CDN provider hints with confidence, not hard claims
- Evidence-weighted exposure/risk scoring: every rule contributes a fixed,
  documented point value to a transparent risk_score, which is then bucketed
  into INFO/LOW/MEDIUM for display (not vulnerability claims)
- Reverse DNS
- JSON / CSV / interactive HTML dashboard reporting (summary cards, sortable
  and filterable results, expandable TLS/certificate + risk-reason detail)
- TOML/JSON configuration
- External probe plugins
- Unit/integration-friendly architecture, covered by an accompanying
  test_mrecon.py test suite

Use only on systems and networks you are authorized to assess.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import importlib.util
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import struct
import ssl
import subprocess
import sys
import threading
from collections import Counter
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import Callable, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import tomllib
except ImportError:
    tomllib = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, Progress
    from rich.panel import Panel
    from rich.markup import escape
except ImportError:
    print("[-] Missing dependency 'rich'. Install via: python -m pip install rich")
    raise SystemExit(1)

# Scapy is optional and intentionally lazy-loaded. Importing it at startup can
# be very slow or hang on some Python/Scapy combinations (notably newer Python
# releases). M-Recon must remain usable for normal TCP/UDP/Web Recon without it.
SCAPY_AVAILABLE = False
SCAPY_STATE = "not_loaded"
SCAPY_ERROR = ""
SCAPY_SOCKET_NAME = ""
IP = IPv6 = TCP = sr1 = sr = send = fragment = conf = None
L3RawSocket = L3pcapSocket = None
SCAPY_L3SOCKET = None

def _probe_scapy_import(timeout_sec: float = 4.0) -> bool:
    """Check Scapy import health in a short-lived helper process.

    This prevents a broken/old Scapy installation from freezing M-Recon at
    startup. The helper is disposable, so a stuck import cannot block the tool.
    """
    try:
        subprocess.run(
            [sys.executable, "-c", "import scapy.all"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, float(timeout_sec)),
            check=False,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False


def _ensure_scapy() -> bool:
    """Load Scapy and select a platform-appropriate layer-3 socket.

    Windows commonly uses Npcap/libpcap through L3pcapSocket, while Unix-like
    systems can use L3RawSocket. Do not reject an otherwise healthy Scapy
    installation merely because L3RawSocket is unavailable on the platform.
    """
    global SCAPY_AVAILABLE, SCAPY_STATE, SCAPY_ERROR, SCAPY_SOCKET_NAME
    global IP, IPv6, TCP, sr1, sr, send, fragment, conf
    global L3RawSocket, L3pcapSocket, SCAPY_L3SOCKET

    if SCAPY_AVAILABLE:
        return True
    if SCAPY_STATE == "unavailable":
        return False
    if not _probe_scapy_import():
        SCAPY_ERROR = "Scapy import self-check failed or timed out"
        SCAPY_STATE = "unavailable"
        return False

    try:
        from scapy.all import IP as _IP, IPv6 as _IPv6, TCP as _TCP
        from scapy.all import sr1 as _sr1, sr as _sr, send as _send, fragment as _fragment
        from scapy.all import conf as _conf
        from scapy.all import L3RawSocket as _L3RawSocket
        try:
            from scapy.all import L3pcapSocket as _L3pcapSocket
        except Exception:
            _L3pcapSocket = None

        IP, IPv6, TCP = _IP, _IPv6, _TCP
        sr1, sr, send, fragment = _sr1, _sr, _send, _fragment
        conf = _conf
        L3RawSocket = _L3RawSocket
        L3pcapSocket = _L3pcapSocket

        if platform.system().lower() == "windows":
            if L3pcapSocket is None:
                raise RuntimeError("Windows SYN scanning requires Scapy's L3pcapSocket (Npcap/libpcap)")
            SCAPY_L3SOCKET = L3pcapSocket
        else:
            if L3RawSocket is None:
                raise RuntimeError("SYN scanning requires Scapy's L3RawSocket on this platform")
            SCAPY_L3SOCKET = L3RawSocket

        SCAPY_SOCKET_NAME = getattr(SCAPY_L3SOCKET, "__name__", type(SCAPY_L3SOCKET).__name__)
        SCAPY_AVAILABLE = True
        SCAPY_STATE = "loaded"
        SCAPY_ERROR = ""
        return True
    except Exception as exc:
        SCAPY_ERROR = f"{type(exc).__name__}: {exc}"
        SCAPY_STATE = "unavailable"
        return False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

console = Console()
USER_AGENT = "M-Recon/15.16"
V15_VERSION = "15.16"


DEFAULT_HTTP_PORTS = {80, 3000, 5000, 8000, 8001, 8008, 8080, 8081, 8888, 18080}
DEFAULT_HTTPS_PORTS = {443, 8443, 9443}
UDP_PROBES = {
    53: bytes.fromhex("0000010000010000000000000377777706676f6f676c6503636f6d0000010001"),
    123: b"\x1b" + b"\x00" * 47,
    161: bytes.fromhex("302602010104067075626c6963a019020400000000020100020100300b300906052b060102010101000500"),
}

WEB_DISCOVERY_MAX_WORDLIST_BYTES = 5 * 1024 * 1024
WEB_DISCOVERY_MAX_WORDS = 20000
WEB_DISCOVERY_FOUND_STATES = {200, 204, 206, 301, 302, 307, 308, 401, 403, 405}


@dataclass
class ScanConfig:
    workers: int = 100
    timeout: float = 0.5
    banner_timeout: float = 1.2
    fingerprint_workers: int = 32
    max_requests_per_second: float = 150.0
    max_http_bytes: int = 65536
    profile: str = "balanced"
    syn_mode: bool = False
    fragment: bool = False
    udp: bool = False
    skip_ping: bool = False
    http: bool = True
    tls: bool = True
    reverse_dns: bool = True
    verify_cert: bool = False
    web_recon: bool = True
    plugins_dir: Optional[str] = None
    output: Optional[str] = None
    large_scan_threshold: int = 5000
    auto_mode: bool = True
    cache: bool = True
    cache_ttl_sec: int = 900
    cache_file: str = ".mrecon_cache.json"
    max_hosts: int = 4096
    explicit_fields: set[str] = field(default_factory=set, repr=False, compare=False)


@dataclass
class ScanStats:
    scheduled: int = 0
    completed: int = 0
    open_tcp: int = 0
    udp_responding: int = 0
    udp_no_response: int = 0
    udp_errors: int = 0
    fingerprinted: int = 0
    errors: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, name: str, amount: int = 1) -> None:
        with self.lock:
            setattr(self, name, getattr(self, name) + amount)


@dataclass
class ServiceResult:
    service: str = "unknown"
    protocol: str = "tcp"
    banner: str = ""
    version: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: str = "low"
    tls: bool = False
    tls_version: str = ""
    tls_cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_san: list[str] = field(default_factory=list)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_sha256: str = ""
    cert_days_left: Optional[int] = None
    cert_verified: Optional[bool] = None
    cert_verify_note: str = ""
    http_status: Optional[int] = None
    http_server: str = ""
    http_title: str = ""
    http_content_type: str = ""
    http_location: str = ""
    waf_provider: str = ""
    waf_confidence: str = "low"
    risk_level: str = "INFO"
    risk_reasons: list[str] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class TLSInfo:
    """TLS/certificate facts for one port, as its own model instead of ~12 flat
    fields bolted onto PortResult. `present=False` means the port isn't TLS at
    all (e.g. plain HTTP, SSH, MySQL) -- every other field is meaningless in
    that case and stays at its default."""
    present: bool = False
    version: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_san: list[str] = field(default_factory=list)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_sha256: str = ""
    cert_days_left: Optional[int] = None
    cert_verified: Optional[bool] = None
    cert_verify_note: str = ""

    @classmethod
    def from_service_result(cls, fp: "ServiceResult") -> "TLSInfo":
        """Build from the flat TLS fields on a fingerprint-stage ServiceResult.
        ServiceResult itself stays flat (it's the fingerprinting engine's
        working type, populated field-by-field as evidence comes in during a
        probe) -- TLSInfo is the tidied-up shape used in the final PortResult
        and everything downstream of it (reports, exports, display)."""
        return cls(
            present=fp.tls, version=fp.tls_version, cipher=fp.tls_cipher,
            cert_subject=fp.cert_subject, cert_issuer=fp.cert_issuer, cert_san=fp.cert_san,
            cert_not_before=fp.cert_not_before, cert_not_after=fp.cert_not_after,
            cert_sha256=fp.cert_sha256, cert_days_left=fp.cert_days_left,
            cert_verified=fp.cert_verified, cert_verify_note=fp.cert_verify_note,
        )


@dataclass
class PortResult:
    """The final, reported shape of one open port.

    Three concerns live here, kept as three clearly separate pieces rather
    than one flat bag of fields: the network/service identity (port,
    protocol, service, banner, confidence, risk, ...) is this dataclass's own
    fields since that IS what a "port result" is; TLS facts are grouped under
    `tls_info`; and Web Recon's output -- itself a whole second-layer result,
    not a handful of extra columns -- lives under `web` as its own typed
    object (or None when Web Recon didn't run for this port). This is meant
    to stay easy to extend on the Web Recon side without every future web
    field becoming a 13th flat attribute here.
    """
    port: int
    protocol: str
    state: str
    target_ip: str
    address_family: str
    hostname: str
    service: str
    version: str
    banner: str
    confidence: str
    evidence: str
    tls_info: TLSInfo
    http_status: Optional[int]
    http_server: str
    http_title: str
    http_content_type: str
    http_location: str
    waf_provider: str
    waf_confidence: str
    risk_level: str
    risk_reasons: list[str]
    risk_score: int
    rtt_ms: float
    web: Optional["WebReconResult"] = None


@dataclass
class WebResource:
    """A single well-known web resource (robots.txt, sitemap.xml, security.txt)
    reported as evidence rather than a bare boolean -- status/size/what-was-in-it,
    not just found=true."""
    found: bool = False
    url: str = ""
    status: Optional[int] = None
    size: int = 0
    evidence: list[str] = field(default_factory=list)


@dataclass
class WebReconResult:
    """Second-layer recon over a confirmed HTTP/HTTPS service on a port.

    Triggered automatically once network recon + fingerprinting confirms a
    port is genuinely serving HTTP/HTTPS (not just guessed by port number) --
    this is not a separate tool the user runs, it's a deeper pass the scanner
    takes on its own evidence.
    """
    target: str = ""
    scheme: str = ""
    final_url: str = ""
    http_status: Optional[int] = None
    title: str = ""
    server: str = ""
    powered_by: str = ""
    tls_version: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    robots_txt: WebResource = field(default_factory=WebResource)
    sitemap_xml: WebResource = field(default_factory=WebResource)
    security_txt: WebResource = field(default_factory=WebResource)
    sitemap_url_count: int = 0
    sitemap_type: str = ""
    sitemap_child_count: int = 0
    sitemap_ref_count: int = 0
    evidence: list[str] = field(default_factory=list)


@dataclass
class Probe:
    name: str
    ports: set[int]
    handler: Callable
    priority: int = 100


class ProbeRegistry:
    def __init__(self):
        self._probes: list[Probe] = []
        self._lock = threading.Lock()

    def register(self, probe: Probe) -> None:
        with self._lock:
            self._probes.append(probe)
            self._probes.sort(key=lambda p: p.priority)

    def candidates(self, port: int) -> list[Probe]:
        with self._lock:
            return [p for p in self._probes if port in p.ports]


class AdaptiveTimeoutManager:
    def __init__(self, initial_rtt: float = 0.5, min_timeout: float = 0.08, max_timeout: float = 2.0):
        self.srtt = max(float(initial_rtt), 0.01)
        self.rttvar = max(self.srtt / 2.0, 0.01)
        self.timeout = self.srtt
        self.min_timeout = max(float(min_timeout), 0.01)
        self.max_timeout = max(float(max_timeout), self.min_timeout)
        self.lock = threading.Lock()

    def update_rtt(self, measured_rtt: float) -> None:
        if measured_rtt <= 0:
            return
        with self.lock:
            alpha, beta = 0.125, 0.25
            self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - measured_rtt)
            self.srtt = (1 - alpha) * self.srtt + alpha * measured_rtt
            self.timeout = max(self.min_timeout, min(self.max_timeout, self.srtt + 4 * self.rttvar))

    def get_timeout(self) -> float:
        with self.lock:
            return self.timeout


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = max(float(rate_per_sec), 0.0)
        self.interval = 1.0 / self.rate if self.rate > 0 else 0.0
        self.lock = threading.Lock()
        self.next_at = time.monotonic()

    def wait(self) -> None:
        if self.rate <= 0:
            return
        with self.lock:
            now = time.monotonic()
            scheduled = max(now, self.next_at)
            self.next_at = scheduled + self.interval
            delay = scheduled - now
        if delay > 0:
            time.sleep(delay)


class FingerprintCache:
    """Small TTL cache for service fingerprints; optional persistent JSON backing.

    Disk writes are debounced and happen OUTSIDE the lock. Holding the lock
    across a full-file json.dumps()+write_text() on every single put() would
    serialize every fingerprinting thread behind disk I/O -- with hundreds of
    ports fingerprinted concurrently, that turns "parallel fingerprinting"
    into "one thread finishes its disk write, then the next one goes".
    """
    def __init__(self, path: str = ".mrecon_cache.json", ttl_sec: int = 900, save_interval_sec: float = 2.0):
        self.path = Path(path)
        self.ttl_sec = max(0, int(ttl_sec))
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self._dirty = False
        self._last_save = 0.0
        self._save_interval = max(0.0, save_interval_sec)
        self._load()

    def _load(self) -> None:
        try:
            if self.path.is_file():
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.data = {}

    def _write_snapshot(self, snapshot: dict) -> None:
        """Serialize and write a given snapshot to disk. Called without the
        lock held -- `snapshot` is this thread's own shallow copy, so nothing
        else can mutate it mid-write."""
        try:
            self.path.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def get(self, key: str) -> Optional[ServiceResult]:
        if self.ttl_sec == 0:
            return None
        now = time.time()
        with self.lock:
            item = self.data.get(key)
            if not item or now - float(item.get("ts", 0)) > self.ttl_sec:
                self.data.pop(key, None)
                return None
            try:
                payload = item["result"]
                return ServiceResult(**payload)
            except Exception:
                return None

    def put(self, key: str, result: ServiceResult) -> None:
        if self.ttl_sec == 0:
            return
        snapshot: Optional[dict] = None
        with self.lock:
            self.data[key] = {"ts": time.time(), "result": asdict(result)}
            self._dirty = True
            now = time.monotonic()
            if now - self._last_save >= self._save_interval:
                self._last_save = now
                self._dirty = False
                # Shallow copy while still holding the lock: cheap, and it
                # freezes the set of keys/values so json.dumps() below can't
                # race with another thread's concurrent dict mutation.
                snapshot = dict(self.data)
        if snapshot is not None:
            self._write_snapshot(snapshot)

    def flush(self) -> None:
        """Force-persist any pending in-memory changes. Call this once a scan
        finishes so results from the last debounce window aren't lost."""
        with self.lock:
            if not self._dirty:
                return
            self._dirty = False
            snapshot = dict(self.data)
        self._write_snapshot(snapshot)


class TLSInspector:
    @staticmethod
    def inspect(sock: socket.socket, server_hostname: Optional[str], timeout: float) -> tuple[socket.socket, ServiceResult]:
        result = ServiceResult(service="tls", protocol="tls", tls=True, confidence="medium")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        wrapped = context.wrap_socket(sock, server_hostname=server_hostname or None)
        wrapped.settimeout(timeout)
        result.tls_version = wrapped.version() or ""
        cipher = wrapped.cipher()
        result.tls_cipher = cipher[0] if cipher else ""
        cert_der = wrapped.getpeercert(binary_form=True)
        if cert_der:
            result.cert_sha256 = hashlib.sha256(cert_der).hexdigest()
            if CRYPTO_AVAILABLE:
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    result.cert_subject = cert.subject.rfc4514_string()
                    result.cert_issuer = cert.issuer.rfc4514_string()
                    if hasattr(cert, "not_valid_before_utc"):
                        # cryptography >= 42: already tz-aware UTC
                        not_before = cert.not_valid_before_utc
                        not_after = cert.not_valid_after_utc
                    else:
                        # cryptography < 42: naive datetimes, documented as UTC wall-clock
                        # values. Attach tzinfo explicitly instead of stripping it from
                        # the other operand -- keeps both code paths on the same
                        # aware-UTC representation regardless of library version.
                        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                    result.cert_not_before = not_before.isoformat()
                    result.cert_not_after = not_after.isoformat()
                    remaining = not_after - datetime.now(timezone.utc)
                    result.cert_days_left = int(remaining.total_seconds() // 86400)
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        result.cert_san = ext.value.get_values_for_type(x509.DNSName)
                    except Exception:
                        pass
                    result.evidence.append("TLS handshake + certificate parse")
                except Exception:
                    result.evidence.append("TLS handshake + certificate fingerprint")
            else:
                result.evidence.append("TLS handshake + certificate fingerprint")
        else:
            result.evidence.append("TLS handshake")
        return wrapped, result

    @staticmethod
    def verify_trust(family: int, ip: str, port: int, server_hostname: Optional[str], timeout: float) -> tuple[Optional[bool], str]:
        """Independent verification-only handshake against the system trust store.

        This opens its own short-lived connection rather than reusing the
        socket from `inspect()`, because a failed verifying handshake tears
        down the connection and would otherwise cost us the unverified
        certificate details `inspect()` already gathered. Returns
        (verified, note); verified is None if the check itself could not run
        (e.g. connection failure unrelated to certificate trust).
        """
        context = ssl.create_default_context()
        if server_hostname:
            context.check_hostname = True
        else:
            context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if family == socket.AF_INET6:
                sock.connect((ip, port, 0, 0))
            else:
                sock.connect((ip, port))
            wrapped = context.wrap_socket(sock, server_hostname=server_hostname or None)
            wrapped.settimeout(timeout)
            wrapped.close()
            return True, "Certificate chain and hostname verified against system trust store"
        except ssl.SSLCertVerificationError as exc:
            return False, f"Certificate verification failed: {exc.verify_message if getattr(exc, 'verify_message', None) else exc}"
        except ssl.SSLError as exc:
            return False, f"TLS error during verification: {exc}"
        except (socket.timeout, OSError) as exc:
            return None, f"Could not complete verification connection: {type(exc).__name__}"
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


class MReconScanner:
    def __init__(self, target_host: str, config: Optional[ScanConfig] = None, registry: Optional[ProbeRegistry] = None):
        self.target_host = target_host
        self.config = config or ScanConfig()
        self.registry = registry or build_default_registry()
        self.max_threads = max(1, min(int(self.config.workers), 256))
        self.fingerprint_workers = max(1, min(int(self.config.fingerprint_workers), 64))
        self.fingerprint_pool = ThreadPoolExecutor(max_workers=self.fingerprint_workers, thread_name_prefix="mrecon-fp")
        self.timeout_manager = AdaptiveTimeoutManager(self.config.timeout)
        self.rate_limiter = RateLimiter(self.config.max_requests_per_second)
        self.banner_timeout = max(0.2, float(self.config.banner_timeout))
        self.stats = ScanStats()
        self.connection_failures = Counter()
        self.cache = FingerprintCache(self.config.cache_file, self.config.cache_ttl_sec) if self.config.cache else None
        self.pause_event = threading.Event(); self.pause_event.set()
        self.stop_event = threading.Event()
        self.results: list[PortResult] = []
        self.lock = threading.Lock()
        self.addresses = self.resolve_addresses(target_host)
        self.hostnames = {ip: self.reverse_dns(ip) if self.config.reverse_dns else "" for _, ip in self.addresses}
        self.os_info = {"guess": "Unknown", "confidence": "low", "method": "TTL heuristic", "observed_ttl": None}

    @staticmethod
    def family_label(family: int) -> str:
        return "IPv6" if family == socket.AF_INET6 else "IPv4"

    def resolve_addresses(self, host: str) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            try:
                ip = ipaddress.ip_address(host)
                return [(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, str(ip))]
            except ValueError:
                console.print(f"[bold red][!] Cannot resolve '{escape(host)}'[/bold red]")
                return []
        seen = set()
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            key = (family, ip)
            if key not in seen:
                seen.add(key)
                out.append(key)
        return out

    @staticmethod
    def reverse_dns(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    @staticmethod
    def _sni_hostname(host: str) -> Optional[str]:
        """Return `host` if it's usable as a TLS SNI server_hostname, or None
        if it's an IP literal.

        RFC 6066 forbids IP addresses in the SNI server_name extension, and
        `ssl.SSLContext.wrap_socket(..., server_hostname=...)` cannot perform
        hostname verification against one either way, so an IP literal must
        always resolve to server_hostname=None -- never to the literal itself.

        The previous check (`host.replace(".", "").isdigit()`) only ever
        caught bare IPv4 literals. It silently failed open for IPv6 literals
        (which contain hex letters and colons, so `.isdigit()` is always
        False for them) as well as bracketed literals like "[::1]" -- both
        would be passed straight through as if they were DNS names. This
        version delegates the actual IP/hostname decision to `ipaddress`,
        which handles IPv4, IPv6, and the bracketed-IPv6 form correctly, and
        treats anything else as a real hostname suitable for SNI.
        """
        candidate = (host or "").strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        # A zone-id suffix (e.g. "fe80::1%eth0") is valid for connecting but
        # not accepted by ipaddress.ip_address(); strip it before the check.
        candidate = candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(candidate)
            return None
        except ValueError:
            return host or None

    @staticmethod
    def guess_ttl(ttl: int) -> tuple[str, str, int]:
        bases = [32, 64, 128, 255]
        base = min((b for b in bases if b >= ttl), default=255)
        distance = base - ttl
        if ttl <= 64:
            guess = "Linux / Unix / macOS"
        elif ttl <= 128:
            guess = "Windows or network appliance"
        else:
            guess = "Network appliance / Unix-like device"
        return guess, "medium" if distance <= 5 else "low", base

    def detect_os_ttl_guess(self) -> dict:
        # A TTL guess is only meaningful on IPv4 and is explicitly heuristic.
        ipv4 = next((ip for family, ip in self.addresses if family == socket.AF_INET), None)
        if not ipv4:
            return self.os_info
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            output = subprocess.check_output(["ping", param, "1", ipv4], stderr=subprocess.STDOUT, timeout=3).decode("utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError):
            return self.os_info
        match = re.search(r"ttl[=|:](\d+)", output, re.IGNORECASE)
        if not match:
            return self.os_info
        ttl = int(match.group(1))
        guess, confidence, base = self.guess_ttl(ttl)
        self.os_info = {"guess": guess, "confidence": confidence, "method": "TTL heuristic", "observed_ttl": ttl, "estimated_initial_ttl": base}
        return self.os_info

    @staticmethod
    def first_line(text: str, limit: int = 180) -> str:
        line = text.strip().splitlines()[0].strip() if text.strip() else ""
        return line[:limit] + "..." if len(line) > limit else line

    @staticmethod
    def service_from_port(port: int, proto: str = "tcp") -> str:
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            return "unknown"

    @staticmethod
    def _abortive_close(sock: Optional[socket.socket]) -> None:
        """Close via RST (SO_LINGER=0) instead of a graceful FIN.

        Used specifically for short-lived discovery/probe connections that are
        about to be replaced with a fresh connection to the same target right
        away. A graceful close here leaves the local side in TIME_WAIT, tying
        up an ephemeral port for ~60s; at high scan rates against many ports,
        that adds up fast and can exhaust the local ephemeral port range. An
        abortive close skips TIME_WAIT entirely. Not used for a scan's final
        close of a port, where a graceful close is preferable and TIME_WAIT
        pressure is not being compounded by an immediate reconnect.
        """
        if sock is None:
            return
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def connect(self, family: int, ip: str, port: int, timeout: float) -> socket.socket:
        self.rate_limiter.wait()
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if family == socket.AF_INET6:
                sock.connect((ip, port, 0, 0))
            else:
                sock.connect((ip, port))
            return sock
        except Exception:
            # Close explicitly and immediately rather than relying on GC to
            # collect the unreferenced socket -- under a large, high-rate scan
            # with many failed connects, waiting on garbage collection timing
            # for fd cleanup is exactly what leads to fd exhaustion.
            try:
                sock.close()
            except OSError:
                pass
            raise

    @staticmethod
    def safe_recv(sock: socket.socket, size: int, timeout: float) -> bytes:
        sock.settimeout(timeout)
        return sock.recv(size)

    @staticmethod
    def parse_http(raw: str) -> tuple[Optional[int], dict[str, str], str]:
        head, _, body = raw.partition("\r\n\r\n")
        lines = head.splitlines()
        status = None
        if lines and lines[0].startswith("HTTP/"):
            m = re.search(r"HTTP/\S+\s+(\d{3})", lines[0])
            if m:
                status = int(m.group(1))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body

    @staticmethod
    def detect_waf(headers: dict[str, str]) -> tuple[str, str, list[str]]:
        joined = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
        checks = [
            ("Cloudflare", ["cf-ray", "cloudflare"], "high"),
            ("Akamai", ["akamai", "x-akamai"], "high"),
            ("Imperva", ["imperva", "incap"], "high"),
            ("AWS CloudFront", ["x-amz-cf-", "cloudfront"], "high"),
            ("Fastly", ["fastly", "x-served-by", "x-cache-hits"], "medium"),
        ]
        for provider, needles, confidence in checks:
            found = [n for n in needles if n in joined]
            if found:
                return provider, confidence, [f"header marker: {x}" for x in found]
        return "", "low", []

    # Evidence-weighted exposure scoring. Each rule below contributes a fixed,
    # documented point value the moment its specific evidence is observed --
    # never a subjective "this feels MEDIUM" judgment. The sum is the
    # `risk_score`: a plain, reproducible number that is comparable and
    # sortable across every result in a scan, not just a discrete bucket.
    # `risk_level` (INFO/LOW/MEDIUM) is then derived from that score purely
    # as a compact display label for the summary table -- the score itself,
    # not the label, is the primary output and is what a caller should use
    # to rank findings. This still deliberately describes *exposure*
    # (something is reachable and identifiable), not a vulnerability claim.
    RISK_WEIGHTS = {
        "cleartext_protocol": 40,
        "http_unencrypted": 10,
        "smb_exposed": 35,
        "remote_access_exposed": 30,
        "redis_unauth_evidence": 35,
        "memcached_exposed": 15,
        "legacy_tls": 30,
        "cert_expired": 35,
        "cert_expiring_soon": 15,
        "cert_untrusted": 30,
    }
    # First (level, min_score) whose threshold the score meets or exceeds wins;
    # checked in order, so keep this sorted from highest threshold to lowest.
    RISK_LEVEL_THRESHOLDS = (("MEDIUM", 30), ("LOW", 10))

    def assess_exposure(self, port: int, service: str, result: ServiceResult) -> tuple[str, list[str], int]:
        """Describe exposure, not vulnerabilities. Returns (level, reasons, score)."""
        score = 0
        reasons: list[str] = []

        def add(weight_key: str, reason: str) -> None:
            nonlocal score
            weight = self.RISK_WEIGHTS[weight_key]
            score += weight
            reasons.append(f"{reason} (+{weight})")

        if port in {21, 23}:
            add("cleartext_protocol", "Cleartext administrative/service protocol exposed")
        if port == 80 and result.http_status is not None:
            add("http_unencrypted", "HTTP service is unencrypted")
        if port in {445, 139} or service == "microsoft-ds":
            add("smb_exposed", "SMB-related service exposed")
        if port in {3389, 5900} and result.service != "unknown":
            add("remote_access_exposed", "Remote access service exposed")
        if service == "redis" and any("PONG" in x.upper() for x in result.evidence):
            add("redis_unauth_evidence", "Redis responded to PING; validate access controls separately")
        if service == "memcached" and result.version:
            add("memcached_exposed", "Memcached service responded to a version probe")
        if result.tls and result.tls_version in {"TLSv1", "TLSv1.1"}:
            add("legacy_tls", f"Legacy TLS protocol observed: {result.tls_version}")
        if result.cert_days_left is not None:
            if result.cert_days_left < 0:
                add("cert_expired", "TLS certificate appears expired")
            elif result.cert_days_left <= 30:
                add("cert_expiring_soon", f"TLS certificate expires in {result.cert_days_left} days")
        if result.cert_verified is False:
            add("cert_untrusted", f"TLS certificate failed trust verification: {result.cert_verify_note}")
        if result.waf_provider:
            # Informational only -- a WAF/CDN hint is not itself exposure evidence,
            # so it doesn't contribute to the score.
            reasons.append(f"WAF/CDN hint: {result.waf_provider} ({result.waf_confidence})")
        if not reasons:
            reasons.append("No notable exposure pattern detected by built-in rules")

        level = "INFO"
        for name, threshold in self.RISK_LEVEL_THRESHOLDS:
            if score >= threshold:
                level = name
                break
        return level, reasons, score

    def probe_ssh(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service="ssh", protocol="ssh", confidence="high")
        raw = self.safe_recv(sock, 1024, self.banner_timeout).decode("utf-8", errors="replace")
        line = self.first_line(raw)
        result.banner = line
        if line.startswith("SSH-"):
            result.version = line[4:].strip()
            result.evidence.append("SSH identification string")
        else:
            result.confidence = "medium"
        return result

    def probe_text(self, sock: socket.socket, port: int) -> ServiceResult:
        probes = {21: b"HELP\r\n", 25: b"EHLO mrecon.local\r\n", 110: b"QUIT\r\n", 143: b"a1 CAPABILITY\r\n"}
        names = {21: "ftp", 25: "smtp", 110: "pop3", 143: "imap"}
        result = ServiceResult(service=names.get(port, self.service_from_port(port)), protocol="tcp", confidence="medium")
        sock.sendall(probes[port])
        raw = self.safe_recv(sock, 4096, self.banner_timeout).decode("utf-8", errors="replace")
        result.banner = self.first_line(raw)
        if result.banner:
            result.evidence.append("protocol response")
            result.confidence = "high"
        return result

    def probe_mysql(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service="mysql", protocol="mysql", confidence="medium")
        raw = self.safe_recv(sock, 4096, self.banner_timeout)
        if len(raw) > 5 and raw[4] == 0x0A:
            version = raw[5:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            result.version = version[:120]
            result.banner = f"MySQL {result.version}"
            result.evidence.append("MySQL handshake greeting")
            result.confidence = "high"
        return result

    def probe_redis(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service="redis", protocol="redis", confidence="medium")
        sock.sendall(b"PING\r\n")
        raw = self.safe_recv(sock, 256, self.banner_timeout).decode("utf-8", errors="replace")
        result.banner = self.first_line(raw)
        if raw.startswith("+PONG"):
            result.evidence.append("Redis PING/PONG")
            result.confidence = "high"
        return result

    def probe_memcached(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service="memcached", protocol="memcached", confidence="medium")
        sock.sendall(b"version\r\n")
        raw = self.safe_recv(sock, 512, self.banner_timeout).decode("utf-8", errors="replace")
        result.banner = self.first_line(raw)
        if raw.upper().startswith("VERSION "):
            result.version = raw.splitlines()[0].split(" ", 1)[1].strip()[:120]
            result.evidence.append("memcached version response")
            result.confidence = "high"
        return result

    # ------------------------------------------------------------------
    # Additional protocol probes.
    #
    # These follow the exact same shape as probe_ssh/probe_mysql/etc. above:
    # take the already-connected socket, speak just enough of the protocol to
    # get a deterministic, low-risk reply, and return a ServiceResult with
    # confidence="high" only once something protocol-specific (not just "the
    # port answered") was actually observed. Adding another protocol is meant
    # to mean "write one probe_xxx method + one registry.register() call in
    # build_default_registry()" -- never a new `if port == ...:` branch in the
    # scanning/dispatch path itself (see _auto_probe_service / fingerprint()),
    # which is exactly the growth pattern this section replaces.
    # ------------------------------------------------------------------

    def probe_postgres(self, sock: socket.socket, port: int) -> ServiceResult:
        """PostgreSQL wire protocol: an SSLRequest is a fixed 8-byte packet
        every PostgreSQL server understands regardless of auth config, and it
        replies with a single unambiguous byte before any authentication is
        attempted -- 'S' (willing to negotiate TLS) or 'N' (plaintext only).
        Both are conclusive evidence of PostgreSQL; anything else is not."""
        result = ServiceResult(service="postgresql", protocol="postgresql", confidence="medium")
        ssl_request = struct.pack("!ii", 8, 80877103)  # length=8, SSLRequest code
        sock.sendall(ssl_request)
        raw = self.safe_recv(sock, 1, self.banner_timeout)
        if raw in (b"S", b"N"):
            result.banner = "PostgreSQL SSLRequest: " + ("willing to negotiate TLS" if raw == b"S" else "plaintext only")
            result.evidence.append("PostgreSQL SSLRequest response")
            result.confidence = "high"
        return result

    def probe_amqp(self, sock: socket.socket, port: int) -> ServiceResult:
        """AMQP (RabbitMQ and compatible brokers): sending the 8-byte protocol
        header gets back either a Connection.Start method frame (begins with
        frame type 0x01) or, if the server insists on a different protocol
        version, an "AMQP" + version echo -- both confirm the service."""
        result = ServiceResult(service="amqp", protocol="amqp", confidence="medium")
        sock.sendall(b"AMQP\x00\x00\x09\x01")
        raw = self.safe_recv(sock, 64, self.banner_timeout)
        if raw.startswith(b"AMQP"):
            result.banner = "AMQP protocol header echoed (version mismatch)"
            result.evidence.append("AMQP protocol header echo")
            result.confidence = "high"
        elif raw[:1] == b"\x01":
            result.banner = "AMQP Connection.Start frame"
            result.evidence.append("AMQP Connection.Start frame")
            result.confidence = "high"
        return result

    def probe_vnc(self, sock: socket.socket, port: int) -> ServiceResult:
        """VNC/RFB servers send their protocol version unprompted as the very
        first bytes on connect, e.g. b"RFB 003.008\\n" -- a pure passive read,
        no bytes sent to the target."""
        result = ServiceResult(service="vnc", protocol="rfb", confidence="medium")
        raw = self.safe_recv(sock, 32, self.banner_timeout).decode("ascii", errors="replace")
        result.banner = self.first_line(raw)
        if raw.startswith("RFB "):
            result.version = raw.strip()[4:]
            result.evidence.append("RFB protocol version banner")
            result.confidence = "high"
        return result

    def probe_rdp(self, sock: socket.socket, port: int) -> ServiceResult:
        """RDP: an X.224 Connection Request wrapped in a TPKT header is
        answered by a matching X.224 Connection Confirm (same TPKT/X.224
        framing bytes) even before any TLS/CredSSP negotiation happens --
        recognizing that fixed reply shape is enough to confirm RDP without
        attempting a real session."""
        result = ServiceResult(service="rdp", protocol="rdp", confidence="medium")
        # TPKT header (version=3, reserved=0, length=19) + X.224 CR TPDU
        # requesting standard RDP security negotiation.
        cr = bytes([
            0x03, 0x00, 0x00, 0x13,  # TPKT: version 3, length 19
            0x0e,                    # X.224 length indicator
            0xe0, 0x00, 0x00, 0x00,  # CR TPDU, dst-ref, src-ref
            0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,  # RDP negotiation request
        ])
        sock.sendall(cr)
        raw = self.safe_recv(sock, 64, self.banner_timeout)
        if len(raw) >= 4 and raw[0] == 0x03 and raw[1] == 0x00:
            result.banner = "X.224 Connection Confirm (TPKT)"
            result.evidence.append("X.224 Connection Confirm reply to RDP negotiation request")
            result.confidence = "high"
        return result

    def probe_mongodb(self, sock: socket.socket, port: int) -> ServiceResult:
        """MongoDB legacy wire protocol: an OP_QUERY "isMaster" against
        admin.$cmd. The reply is a BSON document; rather than parsing BSON,
        just confirm the fixed OP_REPLY header shape (opcode 1) and look for
        the "ismaster"/"maxWireVersion" key names, which is enough evidence
        without a BSON dependency."""
        result = ServiceResult(service="mongodb", protocol="mongodb", confidence="medium")

        def bson_cstring(s: str) -> bytes:
            return s.encode("utf-8") + b"\x00"

        # BSON document: { isMaster: 1 }
        body = struct.pack("<b", 0x10) + bson_cstring("isMaster") + struct.pack("<i", 1)
        bson_doc = struct.pack("<i", len(body) + 5) + body + b"\x00"

        collection = bson_cstring("admin.$cmd")
        op_query_body = struct.pack("<i", 0) + collection + struct.pack("<ii", 0, -1) + bson_doc
        header = struct.pack("<iiii", len(op_query_body) + 16, 0, 0, 2004)  # opCode 2004 = OP_QUERY
        sock.sendall(header + op_query_body)

        raw = self.safe_recv(sock, 2048, self.banner_timeout)
        if len(raw) >= 16:
            msg_len, _, _, op_code = struct.unpack("<iiii", raw[:16])
            if op_code == 1 and (b"ismaster" in raw.lower() or b"maxwireversion" in raw.lower()):
                result.banner = "MongoDB OP_REPLY to isMaster"
                result.evidence.append("MongoDB isMaster OP_REPLY")
                result.confidence = "high"
        return result

    def probe_http(self, sock: socket.socket, port: int, tls: bool = False) -> ServiceResult:
        result = ServiceResult(service="https" if tls else "http", protocol="tls/http" if tls else "http", confidence="high", tls=tls)
        if tls:
            server_hostname = self._sni_hostname(self.target_host)
            peer_family, peer_ip = sock.family, sock.getpeername()[0]
            sock, tls_info = TLSInspector.inspect(sock, server_hostname, self.banner_timeout)
            for key in ("tls_version", "tls_cipher", "cert_subject", "cert_issuer", "cert_not_before", "cert_not_after", "cert_sha256"):
                setattr(result, key, getattr(tls_info, key))
            result.cert_san = tls_info.cert_san
            result.evidence.extend(tls_info.evidence)
            if self.config.verify_cert:
                verified, note = TLSInspector.verify_trust(peer_family, peer_ip, port, server_hostname, self.banner_timeout)
                result.cert_verified = verified
                result.cert_verify_note = note
                result.evidence.append(f"Certificate trust check: {note}")
        default_port = 443 if tls else 80
        host_header = self.target_host if port == default_port else f"{self.target_host}:{port}"
        request = (
            f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        sock.sendall(request)
        data = bytearray()
        limit = max(1024, int(self.config.max_http_bytes))
        while len(data) < limit:
            try:
                chunk = sock.recv(min(8192, limit - len(data)))
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)
        text = bytes(data).decode("iso-8859-1", errors="replace")
        status, headers, body = self.parse_http(text)
        result.http_status = status
        result.http_server = headers.get("server", "")
        result.http_content_type = headers.get("content-type", "")
        result.http_location = headers.get("location", "")
        if result.http_server:
            result.version = result.http_server[:120]
            result.evidence.append("Server header")
        title = re.search(r"<title[^>]*>(.*?)</title>", body[:32768], re.I | re.S)
        if title:
            result.http_title = re.sub(r"\s+", " ", title.group(1)).strip()[:200]
            result.evidence.append("HTML title")
        result.banner = f"HTTP {status}" if status else self.first_line(text)
        result.evidence.append("HTTP response")
        provider, waf_conf, waf_evidence = self.detect_waf(headers)
        result.waf_provider = provider
        result.waf_confidence = waf_conf
        result.evidence.extend(waf_evidence)
        return result

    # ------------------------------------------------------------------
    # Web Recon: a second, automatic pass over any port confirmed as a real
    # HTTP/HTTPS service. Not a separate tool -- triggered from the same scan
    # cycle once fingerprinting has actual evidence (not a guess) that a port
    # speaks HTTP. See run_web_recon() for the orchestration.
    # ------------------------------------------------------------------

    def _web_get(
        self, ip: str, port: int, tls: bool, host_header: str, path: str,
        max_bytes: Optional[int] = None, timeout: Optional[float] = None,
    ) -> tuple[Optional[int], dict[str, str], str, str]:
        """Lightweight one-shot GET for Web Recon sub-fetches (robots.txt, sitemap.xml,
        security.txt, redirect hops, ...). Opens and always closes its own connection;
        returns (None, {}, "", "") on any failure rather than raising, since a missing
        robots.txt/sitemap.xml is an expected, unremarkable outcome, not an error.
        The 4th element is the negotiated TLS version (e.g. "TLSv1.3"), or "" when
        `tls` is False or the handshake didn't get far enough to negotiate one."""
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        to = timeout if timeout is not None else self.banner_timeout
        limit = max(1024, int(max_bytes if max_bytes is not None else self.config.max_http_bytes))
        sock = None
        tls_version = ""
        try:
            sock = self.connect(family, ip, port, to)
            if tls:
                hostname_part = host_header.split(":", 1)[0]
                server_hostname = self._sni_hostname(hostname_part)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=server_hostname or None)
                sock.settimeout(to)
                tls_version = sock.version() or ""
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,*/*\r\nConnection: close\r\n\r\n"
            ).encode("ascii", errors="ignore")
            sock.sendall(request)
            data = bytearray()
            while len(data) < limit:
                try:
                    chunk = sock.recv(min(8192, limit - len(data)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            text = bytes(data).decode("iso-8859-1", errors="replace")
            status, headers, body = self.parse_http(text)
            return status, headers, body, tls_version
        except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
            return None, {}, "", ""
        finally:
            self._abortive_close(sock)

    def _resolve_redirect(
        self, location: str, cur_scheme: str, cur_host_header: str, cur_ip: str, cur_port: int, cur_path: str = "/",
    ) -> Optional[tuple[str, str, bool, str, int, str]]:
        """Resolve a Location header (absolute, scheme-relative, or path-relative)
        against the CURRENT request (scheme + host + path, so a relative redirect
        issued from a non-root path resolves correctly), to a new (scheme,
        host_header, tls, ip, port, path) tuple. Returns None if the target isn't
        http(s) or can't be resolved -- callers treat that as "stop following"."""
        base = f"{cur_scheme}://{cur_host_header}{cur_path}"
        try:
            absolute = urljoin(base, location)
            parsed = urlparse(absolute)
        except ValueError:
            return None
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        new_scheme = parsed.scheme
        new_tls = new_scheme == "https"
        new_host = parsed.hostname
        new_port = parsed.port or (443 if new_tls else 80)
        new_host_header = new_host if new_port in (80, 443) else f"{new_host}:{new_port}"
        new_path = parsed.path or "/"
        if parsed.query:
            new_path += f"?{parsed.query}"
        cur_host_only = cur_host_header.split(":", 1)[0]
        if new_host == cur_host_only:
            new_ip = cur_ip
        else:
            # Redirect points at a different host (e.g. bare domain -> www, or a
            # different domain entirely) -- resolve it fresh rather than reusing
            # the original target's IP.
            try:
                infos = socket.getaddrinfo(new_host, new_port, proto=socket.IPPROTO_TCP)
                new_ip = infos[0][4][0]
            except socket.gaierror:
                return None
        return new_scheme, new_host_header, new_tls, new_ip, new_port, new_path

    @staticmethod
    def _detect_technologies(headers: dict[str, str], body: str) -> list[str]:
        """Header/body based technology hints. Deliberately conservative pattern
        matching (same spirit as detect_waf) -- these are hints, not fingerprints
        with version-exploit implications."""
        techs: list[str] = []
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        combined_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        server_powered = f"{server} {powered}".lower()
        simple_checks = [
            ("nginx", "nginx"), ("apache", "Apache"), ("microsoft-iis", "IIS"),
            ("php", "PHP"), ("express", "Express"), ("openresty", "OpenResty"),
            ("cloudflare", "Cloudflare"), ("varnish", "Varnish"), ("gunicorn", "Gunicorn"),
            ("werkzeug", "Werkzeug/Flask"),
        ]
        for needle, label in simple_checks:
            if needle in server_powered:
                techs.append(label)
        if "x-drupal-cache" in combined_headers or "x-generator: drupal" in combined_headers:
            techs.append("Drupal")
        if "x-aspnet-version" in combined_headers or "asp.net" in server_powered:
            techs.append("ASP.NET")
        if re.search(r"set-cookie:[^\r\n]*phpsessid", combined_headers):
            techs.append("PHP (session cookie)")
        body_head = body[:65536]
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body_head, re.I)
        if gen_match:
            g = re.sub(r"\s+", " ", gen_match.group(1)).strip()[:80]
            if g:
                techs.append(g)
        elif "wp-content" in body_head.lower() or "wp-includes" in body_head.lower():
            techs.append("WordPress")
        seen: set[str] = set()
        deduped: list[str] = []
        for t in techs:
            if t.lower() not in seen:
                seen.add(t.lower())
                deduped.append(t)
        return deduped

    def run_web_recon(self, ip: str, port: int, tls: bool) -> WebReconResult:
        """Second-layer recon over a port already confirmed to speak HTTP/HTTPS.

        Follows redirects (bounded), then collects robots.txt / sitemap.xml /
        security.txt as evidence-bearing findings rather than booleans, and
        surfaces lightweight technology hints. Never raises -- any fetch failure
        just leaves that piece of the result at its "not found" default.
        """
        result = WebReconResult()
        default_port = 443 if tls else 80
        host_header = self.target_host if port == default_port else f"{self.target_host}:{port}"
        scheme = "https" if tls else "http"
        result.target = self.target_host
        result.scheme = scheme

        cur_scheme, cur_host_header, cur_tls, cur_ip, cur_port = scheme, host_header, tls, ip, port
        cur_path = "/"
        status: Optional[int] = None
        headers: dict[str, str] = {}
        body = ""
        negotiated_tls_version = ""
        visited: set[str] = set()
        for _ in range(5):
            url = f"{cur_scheme}://{cur_host_header}{cur_path}"
            if url in visited:
                result.evidence.append(f"Redirect loop detected at {url}; stopped following")
                break
            visited.add(url)
            status, headers, body, negotiated_tls_version = self._web_get(cur_ip, cur_port, cur_tls, cur_host_header, cur_path)
            if status is None:
                break
            if status in (301, 302, 303, 307, 308) and headers.get("location"):
                location = headers["location"]
                resolved = self._resolve_redirect(location, cur_scheme, cur_host_header, cur_ip, cur_port, cur_path)
                result.redirect_chain.append(f"{url} -> {status} -> {location}")
                if resolved is None:
                    break
                cur_scheme, cur_host_header, cur_tls, cur_ip, cur_port, cur_path = resolved
                continue
            break

        result.final_url = f"{cur_scheme}://{cur_host_header}{cur_path}"
        result.http_status = status
        if status is None:
            result.evidence.append("Could not confirm an HTTP response on this port; web recon skipped")
            return result

        result.server = headers.get("server", "")
        result.powered_by = headers.get("x-powered-by", "")
        if cur_tls:
            result.tls_version = negotiated_tls_version
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body[:65536], re.I | re.S)
        if title_match:
            result.title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200]

        result.technologies = self._detect_technologies(headers, body)
        if result.technologies:
            result.evidence.append("headers/body -> " + ", ".join(result.technologies))
        if result.server:
            result.evidence.append(f"headers -> Server: {result.server}")

        # robots.txt -- also mine it for an authoritative Sitemap: reference
        # instead of only ever guessing the default /sitemap.xml path.
        r_status, r_headers, r_body, _ = self._web_get(cur_ip, cur_port, cur_tls, cur_host_header, "/robots.txt")
        result.robots_txt.status = r_status
        sitemap_refs: list[str] = []
        # A catch-all server (e.g. an SPA serving index.html for any path) can
        # return 200 for /robots.txt without it actually being a robots file --
        # require it to actually look like one, not just a non-empty 200 body.
        looks_like_robots = bool(re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", r_body))
        if r_status == 200 and looks_like_robots:
            result.robots_txt.found = True
            result.robots_txt.size = len(r_body)
            result.robots_txt.url = f"{cur_scheme}://{cur_host_header}/robots.txt"
            disallow_lines = [ln.strip() for ln in r_body.splitlines() if ln.strip().lower().startswith("disallow:")]
            sitemap_lines = [ln.strip() for ln in r_body.splitlines() if ln.strip().lower().startswith("sitemap:")]
            for ln in sitemap_lines:
                ref = ln.split(":", 1)[1].strip()
                if ref:
                    sitemap_refs.append(ref)
            if disallow_lines:
                result.robots_txt.evidence.append(f"{len(disallow_lines)} Disallow rule(s), e.g. {disallow_lines[0]}")
            if sitemap_lines:
                result.robots_txt.evidence.append(f"Sitemap reference(s): {len(sitemap_lines)}")
                result.evidence.append("robots -> Sitemap detected")
            result.sitemap_ref_count = len(sitemap_lines)

        # sitemap.xml -- prefer the reference robots.txt gave us, if any.
        sitemap_path = "/sitemap.xml"
        sm_scheme, sm_host_header, sm_tls, sm_ip, sm_port = cur_scheme, cur_host_header, cur_tls, cur_ip, cur_port
        if sitemap_refs:
            resolved = self._resolve_redirect(sitemap_refs[0], cur_scheme, cur_host_header, cur_ip, cur_port, cur_path)
            if resolved is not None:
                sm_scheme, sm_host_header, sm_tls, sm_ip, sm_port, sitemap_path = resolved
        s_status, s_headers, s_body, _ = self._web_get(sm_ip, sm_port, sm_tls, sm_host_header, sitemap_path)
        result.sitemap_xml.status = s_status
        # Same catch-all-server concern as robots.txt: require actual sitemap
        # markup, not just a 200 with some body.
        looks_like_sitemap = bool(re.search(r"(?i)<(urlset|sitemapindex|loc)\b", s_body))
        if s_status == 200 and looks_like_sitemap:
            result.sitemap_xml.found = True
            result.sitemap_xml.size = len(s_body)
            result.sitemap_xml.url = f"{sm_scheme}://{sm_host_header}{sitemap_path}"
            loc_count = len(re.findall(r"<loc>", s_body, re.I))
            is_index = bool(re.search(r"<sitemapindex\b", s_body, re.I))
            # A sitemap INDEX lists other sitemap files, not pages -- counting
            # its <loc> entries as "URLs" would misreport how big the site is.
            # Keep the two counts distinct instead of overloading one field;
            # deliberately not fetching the child sitemaps themselves (that's
            # the line between "recon" and "building a crawler").
            if is_index:
                result.sitemap_type = "sitemapindex"
                result.sitemap_child_count = loc_count
                result.sitemap_url_count = 0
                result.sitemap_xml.evidence.append(f"Sitemap index referencing {loc_count} child sitemap(s)")
                result.evidence.append(f"sitemap -> index referencing {loc_count} sitemap(s)")
            else:
                result.sitemap_type = "urlset"
                result.sitemap_url_count = loc_count
                result.sitemap_child_count = 0
                result.sitemap_xml.evidence.append(f"{loc_count} URL(s) listed")
                result.evidence.append(f"sitemap -> {loc_count} URLs")

        # security.txt -- RFC 9116 prefers /.well-known/security.txt, with
        # /security.txt as the legacy fallback location.
        sec_status, sec_headers, sec_body, _ = self._web_get(cur_ip, cur_port, cur_tls, cur_host_header, "/.well-known/security.txt")
        sec_path = "/.well-known/security.txt"
        if sec_status != 200:
            sec_status, sec_headers, sec_body, _ = self._web_get(cur_ip, cur_port, cur_tls, cur_host_header, "/security.txt")
            sec_path = "/security.txt"
        result.security_txt.status = sec_status
        looks_like_security_txt = bool(re.search(
            r"(?im)^\s*(contact|expires|encryption|policy|acknowledgments|hiring|canonical)\s*:", sec_body
        ))
        if sec_status == 200 and looks_like_security_txt:
            result.security_txt.found = True
            result.security_txt.size = len(sec_body)
            result.security_txt.url = f"{cur_scheme}://{cur_host_header}{sec_path}"
            contact_lines = [ln.strip() for ln in sec_body.splitlines() if ln.strip().lower().startswith("contact:")]
            expires_lines = [ln.strip() for ln in sec_body.splitlines() if ln.strip().lower().startswith("expires:")]
            if contact_lines:
                result.security_txt.evidence.append(contact_lines[0])
            if expires_lines:
                result.security_txt.evidence.append(expires_lines[0])

        return result

    @staticmethod
    def _normalize_discovery_path(word: str) -> Optional[str]:
        word = word.strip()
        if not word or word.startswith("#"):
            return None
        if len(word) > 2048:
            return None
        parsed = urlparse(word)
        if parsed.scheme or parsed.netloc:
            return None
        path = parsed.path.strip()
        if not path:
            return None
        path = "/" + path.lstrip("/")
        path = re.sub(r"/{2,}", "/", path)
        if parsed.query:
            path += "?" + parsed.query
        return path

    def _web_discovery_get(
        self, ip: str, port: int, tls: bool, host_header: str, path: str,
    ) -> tuple[Optional[int], dict[str, str], bytes]:
        """GET one discovery path without exposing or storing response content.

        A small byte cap plus a Range header keeps content discovery metadata-only:
        we need status/headers/size/signature, not the page/file contents.
        """
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock: Optional[socket.socket] = None
        timeout = self.banner_timeout
        limit = min(max(1024, int(self.config.max_http_bytes)), 8192)
        try:
            sock = self.connect(family, ip, port, timeout)
            if tls:
                hostname_part = host_header.split(":", 1)[0]
                server_hostname = self._sni_hostname(hostname_part)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=server_hostname or None)
                sock.settimeout(timeout)
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\n"
                f"Range: bytes=0-{limit - 1}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            ).encode("ascii", errors="ignore")
            sock.sendall(request)
            data = bytearray()
            while len(data) < limit:
                try:
                    chunk = sock.recv(min(4096, limit - len(data)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            raw = bytes(data)
            text = raw.decode("iso-8859-1", errors="replace")
            status, headers, body = self.parse_http(text)
            return status, headers, body.encode("iso-8859-1", errors="replace")
        except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
            return None, {}, b""
        finally:
            self._abortive_close(sock)

    @staticmethod
    def _discovery_body_signature(status: Optional[int], headers: dict[str, str], body: bytes) -> tuple:
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        text = body.decode("iso-8859-1", errors="ignore")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text[:32768], re.I | re.S)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower()[:120] if title_match else ""
        size_bucket = len(body) // 256
        return status, content_type, title, size_bucket

    def discover_web_content(self, ip: str, port: int, tls: bool, words: list[str]) -> dict:
        """Run metadata-only content discovery against one confirmed web service.

        Only relevant response codes are returned. 404s and ordinary failures are
        intentionally suppressed. A random baseline request filters common soft-404
        pages so a catch-all application does not turn the wordlist into noise.
        """
        default_port = 443 if tls else 80
        host_header = self.target_host if port == default_port else f"{self.target_host}:{port}"
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in words:
            path = self._normalize_discovery_path(raw)
            if path and path not in seen:
                seen.add(path)
                normalized.append(path)
        if not normalized:
            return {"target": self.target_host, "port": port, "found": [], "tested": 0, "skipped": len(words)}

        # Bound the feature so a very large wordlist cannot silently become an
        # unbounded request generator. Reuse the scanner's rate limiter.
        normalized = normalized[:WEB_DISCOVERY_MAX_WORDS]
        baseline_token = f"/__mrecon_not_found_{hashlib.sha256(f'{time.monotonic_ns()}:{ip}:{port}'.encode()).hexdigest()[:16]}"
        baseline_status, baseline_headers, baseline_body = self._web_discovery_get(
            ip, port, tls, host_header, baseline_token
        )
        baseline_sig = self._discovery_body_signature(baseline_status, baseline_headers, baseline_body) if baseline_status is not None else None

        def check(path: str) -> Optional[dict]:
            status, headers, body = self._web_discovery_get(ip, port, tls, host_header, path)
            if status not in WEB_DISCOVERY_FOUND_STATES:
                return None
            if status == 200 and baseline_sig is not None:
                candidate_sig = self._discovery_body_signature(status, headers, body)
                if candidate_sig == baseline_sig:
                    return None
            location = headers.get("location", "").strip()
            content_type = headers.get("content-type", "").split(";", 1)[0].strip()
            return {
                "path": path,
                "status": status,
                "size": len(body),
                "content_type": content_type,
                "location": location[:200],
            }

        found: list[dict] = []
        worker_count = max(1, min(self.max_threads, 16))
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="mrecon-tr") as pool:
            futures = {pool.submit(check, path): path for path in normalized}
            for future in as_completed(futures):
                try:
                    item = future.result()
                except Exception:
                    item = None
                if item is not None:
                    found.append(item)

        found.sort(key=lambda x: (int(x["status"]), x["path"]))
        return {
            "target": self.target_host,
            "port": port,
            "tested": len(normalized),
            "skipped": max(0, len(words) - len(normalized)),
            "found": found,
        }

    def generic_probe(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service=self.service_from_port(port), protocol="tcp", confidence="low")
        try:
            raw = self.safe_recv(sock, 2048, self.banner_timeout).decode("utf-8", errors="replace")
        except (socket.timeout, OSError):
            raw = ""
        if raw:
            result.banner = self.first_line(raw)
            result.evidence.append("passive banner")
            result.confidence = "medium"
        return result

    def _try_http(self, family: int, ip: str, port: int, tls: bool) -> Optional[ServiceResult]:
        sock = None
        try:
            sock = self.connect(family, ip, port, self.banner_timeout)
            result = self.probe_http(sock, port, tls=tls)
            return result if result.http_status is not None or result.tls else None
        except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def _cache_key(self, family: int, ip: str, port: int) -> str:
        return f"{V15_VERSION}:{family}:{ip}:{port}:{self.config.profile}"

    @staticmethod
    def _looks_like_http_service(port: int, banner: str = "", evidence: Optional[list[str]] = None) -> bool:
        b = (banner or "").lower()
        e = " ".join(evidence or []).lower()
        return port in DEFAULT_HTTP_PORTS or any(x in b for x in ("http/", "server:", "html")) or "http response" in e

    def _try_passive(self, sock: socket.socket, port: int) -> ServiceResult:
        result = ServiceResult(service=self.service_from_port(port), protocol="tcp", confidence="low")
        try:
            raw = self.safe_recv(sock, 2048, self.banner_timeout).decode("utf-8", errors="replace")
        except (socket.timeout, OSError):
            raw = ""
        if raw:
            result.banner = self.first_line(raw)
            result.evidence.append("passive banner")
            result.confidence = "medium"
            if result.banner.startswith("SSH-"):
                result.service = "ssh"; result.protocol = "ssh"; result.version = result.banner[4:].strip(); result.confidence = "high"
            elif result.banner.startswith("HTTP/"):
                result.service = "http"; result.protocol = "http"; result.confidence = "high"
        return result

    def _auto_probe_service(self, family: int, ip: str, port: int) -> ServiceResult:
        """Probe only when evidence/port suggests it; progressively deepen in deep profile."""
        sock = None
        try:
            sock = self.connect(family, ip, port, self.banner_timeout)
            passive = self._try_passive(sock, port)
            if passive.confidence == "high":
                return passive

            # `passive`'s read has already drained whatever the server sent on this
            # connection. Protocol-specific probes below (MySQL, SSH, FTP/SMTP/POP3/
            # IMAP, ...) rely on reading the server's own greeting -- on the same,
            # now-empty connection they would always see nothing and stay stuck at
            # "medium" confidence no matter how real the service is. Reconnecting
            # gives each candidate probe a genuinely fresh handshake to read.
            self._abortive_close(sock)
            sock = self.connect(family, ip, port, self.banner_timeout)

            candidates = self.registry.candidates(port)
            best_guess: Optional[ServiceResult] = None
            for probe in candidates:
                # HTTPS is handled separately below (needs its own TLS-wrapped
                # socket), so skip it here rather than probing plaintext HTTP
                # semantics over what may be a TLS port.
                if probe.name == "https":
                    continue
                try:
                    candidate_result = probe.handler(self, sock, port)
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    candidate_result = None
                if candidate_result is not None and candidate_result.confidence == "high":
                    # Protocol actually confirmed (real handshake/greeting match) --
                    # safe to commit to this result immediately.
                    return candidate_result
                if candidate_result is not None and best_guess is None:
                    # The probe ran but never confirmed the protocol (e.g. no MySQL
                    # greeting, no SSH banner). Keep it as a fallback label only --
                    # do NOT return it yet, since committing here previously meant
                    # a port-based guess with zero evidence would permanently block
                    # a more accurate identification (e.g. a plain HTTP admin panel
                    # squatting on port 3306) from ever being attempted below.
                    best_guess = candidate_result
                # The socket may already have protocol-specific bytes written to it
                # (e.g. "PING\r\n" sent to something that wasn't Redis) or already been
                # read from -- get a fresh connection before trying the next probe or
                # the generic HTTP/TLS fallbacks below.
                self._abortive_close(sock)
                sock = self.connect(family, ip, port, self.banner_timeout)

            if self.config.http and self.config.profile != "fast":
                try:
                    http = self.probe_http(sock, port, tls=False)
                    if http.http_status is not None:
                        return http
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    pass

            if self.config.tls and (port in DEFAULT_HTTPS_PORTS or self.config.profile == "deep"):
                try:
                    self._abortive_close(sock)
                    sock = self.connect(family, ip, port, self.banner_timeout)
                    tls = self.probe_http(sock, port, tls=True)
                    if tls.tls:
                        return tls
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    pass

            if best_guess is not None:
                # The port-specific probe may have re-read the connection after
                # `passive` already captured real banner text -- don't discard that
                # just because the protocol-specific parser didn't recognize it.
                if not best_guess.banner and passive.banner:
                    best_guess.banner = passive.banner
                    best_guess.evidence.append("banner captured before protocol-specific probe")
                best_guess.evidence.append("unconfirmed: port-based guess only, no protocol handshake matched")
                return best_guess

            return passive
        finally:
            if sock:
                try: sock.close()
                except OSError: pass

    def fingerprint(self, family: int, ip: str, port: int) -> ServiceResult:
        key = self._cache_key(family, ip, port)
        if self.cache:
            cached = self.cache.get(key)
            if cached:
                cached.evidence = list(cached.evidence) + ["fingerprint cache"]
                return cached
        result = self._auto_probe_service(family, ip, port)
        if self.cache:
            self.cache.put(key, result)
        return result

    def append_tcp_open(self, family: int, ip: str, port: int, elapsed: float) -> None:
        self.fingerprint_pool.submit(self._fingerprint_and_record, family, ip, port, elapsed)

    def _fingerprint_and_record(self, family: int, ip: str, port: int, elapsed: float) -> None:
        """Pipeline coordinator for one confirmed-open port: Fingerprint -> Web
        Recon -> Result Assembly. (Discovery already happened in
        scan_tcp_connect, which is what got us here.) Each stage is its own
        method so this method's job is orchestration, not doing the work
        itself -- fingerprinting, deciding whether/how to run Web Recon, and
        building the final PortResult are separable concerns even though they
        currently all execute within this one worker call.
        """
        try:
            fp = self._stage_fingerprint(family, ip, port)
            web_recon_data = self._stage_web_recon(fp, ip, port)
            item = self._stage_assemble_result(family, ip, port, elapsed, fp, web_recon_data)
            with self.lock:
                self.results.append(item)
            self.stats.inc("open_tcp")
        except Exception as exc:
            self.stats.inc("errors")
            logging.getLogger("mrecon").error("Fingerprint worker error for %s:%d: %s", ip, port, exc)

    def _stage_fingerprint(self, family: int, ip: str, port: int) -> ServiceResult:
        """Pipeline stage: Fingerprint. Identifies the service on an already-open
        port and scores its exposure risk. Raises on unexpected failure --
        the caller (the pipeline coordinator) is responsible for turning that
        into a counted error rather than a crash."""
        fp = self.fingerprint(family, ip, port)
        self.stats.inc("fingerprinted")
        fp.risk_level, fp.risk_reasons, fp.risk_score = self.assess_exposure(port, fp.service, fp)
        return fp

    def _stage_web_recon(self, fp: ServiceResult, ip: str, port: int) -> Optional[WebReconResult]:
        """Pipeline stage: Web Recon. Only runs once Fingerprint has *confirmed*
        HTTP/HTTPS (confidence == "high", i.e. an actual HTTP response was
        parsed or TLS+HTTP matched) -- never on a port-number guess, and never
        in "fast" profile where the point is to stay fast. A Web Recon failure
        here is swallowed (logged at debug level) rather than failing the
        whole port: Web Recon is an enrichment on top of a confirmed result,
        not a precondition for reporting it.

        Input: the confirmed fingerprint (fp) plus where to connect (ip, port).
        Output: a WebReconResult, or None if Web Recon didn't run/didn't get
        far enough to say anything. Never a raw dict -- dict conversion is a
        serialization concern that belongs at the report/export boundary, not
        baked into what this stage hands the next one.
        """
        if not (
            self.config.web_recon
            and self.config.profile != "fast"
            and fp.service in ("http", "https")
            and fp.confidence == "high"
        ):
            return None
        try:
            return self.run_web_recon(ip, port, tls=fp.tls)
        except Exception as exc:
            logging.getLogger("mrecon").debug("Web recon error for %s:%d: %s", ip, port, exc)
            return None

    def _stage_assemble_result(
        self, family: int, ip: str, port: int, elapsed: float,
        fp: ServiceResult, web_recon_result: Optional[WebReconResult],
    ) -> PortResult:
        """Pipeline stage: Result Assembly. Pure construction -- takes what
        Fingerprint and Web Recon produced and shapes it into the PortResult
        the rest of the tool (reporting, export, the interactive shell)
        consumes. No scanning or network I/O happens here.

        Input: the confirmed fingerprint (fp) and optional Web Recon result.
        Output: one PortResult, with TLS facts grouped under `tls_info` and
        the Web Recon result (if any) attached as its own typed object under
        `web` -- not flattened into this dataclass's own namespace.
        """
        return PortResult(
            port=port, protocol=fp.protocol, state="OPEN", target_ip=ip,
            address_family=self.family_label(family), hostname=self.hostnames.get(ip, "N/A"),
            service=fp.service, version=fp.version, banner=fp.banner,
            confidence=fp.confidence, evidence="; ".join(fp.evidence),
            tls_info=TLSInfo.from_service_result(fp),
            http_status=fp.http_status,
            http_server=fp.http_server, http_title=fp.http_title,
            http_content_type=fp.http_content_type, http_location=fp.http_location,
            waf_provider=fp.waf_provider, waf_confidence=fp.waf_confidence,
            risk_level=fp.risk_level, risk_reasons=fp.risk_reasons, risk_score=fp.risk_score,
            rtt_ms=round(elapsed * 1000, 2),
            web=web_recon_result,
        )

    def scan_tcp_connect(self, family: int, ip: str, port: int) -> None:
        start = time.monotonic()
        sock = None
        try:
            self.rate_limiter.wait()
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_manager.get_timeout())
            if family == socket.AF_INET6:
                code = sock.connect_ex((ip, port, 0, 0))
            else:
                code = sock.connect_ex((ip, port))
            elapsed = time.monotonic() - start
            if code == 0:
                self.timeout_manager.update_rtt(elapsed)
                # Release the discovery connection before fingerprinting.
                # This matters for single-threaded services such as the stdlib HTTP server.
                # Abortive (RST) close: a fresh connection is opened again right
                # away for fingerprinting, so there's no benefit to a graceful
                # FIN close here, only local TIME_WAIT cost.
                self._abortive_close(sock)
                sock = None
                self.append_tcp_open(family, ip, port, elapsed)
            else:
                with self.lock:
                    self.connection_failures[str(code)] += 1
        except OSError as exc:
            with self.lock:
                self.connection_failures[type(exc).__name__] += 1
        except Exception as exc:
            with self.lock:
                self.connection_failures[type(exc).__name__] += 1
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def scan_tcp_syn(self, family: int, ip: str, port: int) -> None:
        # Current SYN implementation is IPv4-only; IPv6 continues to use the
        # safe TCP-connect fallback. On Windows, Scapy uses Npcap/libpcap via
        # L3pcapSocket; Unix-like systems use L3RawSocket.
        if family != socket.AF_INET or not _ensure_scapy():
            self.scan_tcp_connect(family, ip, port)
            return
        start = time.monotonic()
        timeout = self.timeout_manager.get_timeout()
        self.rate_limiter.wait()
        try:
            if SCAPY_L3SOCKET is not None:
                conf.L3socket = SCAPY_L3SOCKET
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            if self.config.fragment:
                answered, _ = sr(fragment(pkt, fragsize=8), timeout=timeout, verbose=0)
                response = answered[0][1] if answered else None
            else:
                response = sr1(pkt, timeout=timeout, verbose=0)
            if response is not None and response.haslayer(TCP):
                flags = int(response[TCP].flags)
                if (flags & 0x12) == 0x12:
                    rst = IP(dst=ip) / TCP(dport=port, flags="R", ack=int(response[TCP].seq) + 1)
                    send(rst, verbose=0)
                    elapsed = time.monotonic() - start
                    self.timeout_manager.update_rtt(elapsed)
                    self.append_tcp_open(family, ip, port, elapsed)
        except Exception as exc:
            # Any Scapy/socket/runtime failure falls back to a normal connect scan,
            # but preserve the concrete reason for diagnostics instead of hiding it.
            logging.getLogger("mrecon").debug(
                "SYN probe failed for %s:%d (%s): %s; falling back to TCP connect",
                ip, port, type(exc).__name__, exc,
            )
            self.scan_tcp_connect(family, ip, port)

    @staticmethod
    def classify_udp_reply(port: int, data: bytes) -> tuple[str, str, str, list[str]]:
        service = MReconScanner.service_from_port(port, "udp")
        evidence: list[str] = []
        if port == 53 and len(data) >= 12:
            return "dns", "udp/dns", "high", ["DNS response header"]
        if port == 123 and len(data) >= 48:
            return "ntp", "udp/ntp", "high", ["NTP response packet"]
        if port == 161 and data.startswith(b"0"):
            return "snmp", "udp/snmp", "high", ["SNMP BER sequence"]
        if data:
            evidence.append("UDP response")
        return service, "udp", "medium" if data else "low", evidence

    @staticmethod
    def udp_probe_name(port: int) -> str:
        return {53: "DNS", 123: "NTP", 161: "SNMP"}.get(port, "UDP")

    def record_udp_result(
        self,
        ip: str,
        port: int,
        state: str,
        confidence: str,
        evidence: str,
        risk_reasons: list[str],
        elapsed: float,
        service: str = "unknown",
        protocol: str = "udp",
        banner: str = "",
    ) -> None:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        item = PortResult(
            port=port, protocol=protocol, state=state, target_ip=ip,
            address_family=self.family_label(family), hostname=self.hostnames.get(ip, "N/A"),
            service=service, version="", banner=banner, confidence=confidence, evidence=evidence,
            tls_info=TLSInfo(), http_status=None, http_server="",
            http_title="", http_content_type="", http_location="", waf_provider="", waf_confidence="low",
            risk_level="INFO", risk_reasons=risk_reasons, risk_score=0, rtt_ms=round(elapsed * 1000, 2)
        )
        with self.lock:
            self.results.append(item)

    def scan_udp(self, ip: str, port: int) -> None:
        probe = UDP_PROBES.get(port)
        if probe is None:
            return
        self.rate_limiter.wait()
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        timeout = self.timeout_manager.get_timeout()
        sock.settimeout(timeout)
        start = time.monotonic()
        probe_name = self.udp_probe_name(port)
        service_hint = self.service_from_port(port, "udp")
        try:
            target = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
            sock.sendto(probe, target)
            data, _ = sock.recvfrom(4096)
            elapsed = time.monotonic() - start
            service, protocol, confidence, evidence = self.classify_udp_reply(port, data)
            self.record_udp_result(
                ip, port, "OPEN (response)", confidence, "; ".join(evidence) or f"{probe_name} response",
                ["UDP service responded to a protocol-aware probe"], elapsed,
                service=service, protocol=protocol, banner=data[:64].hex(),
            )
            self.stats.inc("udp_responding")
        except socket.timeout:
            elapsed = time.monotonic() - start
            self.record_udp_result(
                ip, port, "NO RESPONSE", "low",
                f"{probe_name} probe sent; no response within {timeout:.2f}s",
                ["No UDP response; port may be filtered, closed, or service may not answer this probe"], elapsed,
                service=service_hint,
            )
            self.stats.inc("udp_no_response")
        except OSError as exc:
            elapsed = time.monotonic() - start
            self.record_udp_result(
                ip, port, "ERROR", "low",
                f"{probe_name} probe error: {type(exc).__name__}: {exc}",
                ["Local/network socket error while sending UDP probe"], elapsed,
                service=service_hint,
            )
            self.stats.inc("udp_errors")
        finally:
            sock.close()

    def apply_profile(self) -> None:
        """Apply profile defaults only where the user left the value in AUTO."""
        explicit = self.config.explicit_fields
        if self.config.profile == "fast":
            if "banner_timeout" not in explicit:
                self.config.banner_timeout = min(self.config.banner_timeout, 0.8)
            if "fingerprint_workers" not in explicit:
                self.config.fingerprint_workers = min(self.config.fingerprint_workers, 16)
        elif self.config.profile == "deep":
            if "banner_timeout" not in explicit:
                self.config.banner_timeout = max(self.config.banner_timeout, 2.0)
            if "fingerprint_workers" not in explicit:
                self.config.fingerprint_workers = min(max(self.config.fingerprint_workers, 32), 64)
            if "max_http_bytes" not in explicit:
                self.config.max_http_bytes = max(self.config.max_http_bytes, 131072)

    def run(self, ports: list[int], output_file: Optional[str] = None, display: bool = True) -> dict:
        if not self.addresses:
            return {}
        self.apply_profile()
        scan_start = time.monotonic()
        if self.config.syn_mode:
            if not _ensure_scapy():
                logging.getLogger("mrecon").warning(
                    "SYN scan (-S) unavailable: %s; falling back to TCP connect scan.",
                    SCAPY_ERROR or "Scapy health check failed",
                )
                self.config.syn_mode = False
            elif hasattr(os, "geteuid") and os.geteuid() != 0:
                # Unix raw sockets normally require root. Windows does not expose
                # geteuid(); Npcap/libpcap handles packet access on supported setups.
                logging.getLogger("mrecon").warning(
                    "SYN scan (-S) requires root/administrator privileges for raw sockets; "
                    "falling back to TCP connect scan. Re-run with sudo to use -S."
                )
                self.config.syn_mode = False
            else:
                try:
                    conf.L3socket = SCAPY_L3SOCKET
                except Exception as exc:
                    logging.getLogger("mrecon").warning(
                        "Could not activate SYN socket %s: %s; falling back to TCP connect scan.",
                        SCAPY_SOCKET_NAME or "unknown", exc,
                    )
                    self.config.syn_mode = False
        scan_jobs = [(family, ip, port, "tcp") for family, ip in self.addresses for port in ports]
        if self.config.udp:
            udp_ports = [p for p in ports if p in UDP_PROBES]
            scan_jobs.extend((socket.AF_INET6 if ":" in ip else socket.AF_INET, ip, p, "udp") for _, ip in self.addresses for p in udp_ports)
        self.stats.scheduled = len(scan_jobs)
        os_ttl_thread: Optional[threading.Thread] = None
        if not self.config.skip_ping:
            # detect_os_ttl_guess() shells out to `ping` with up to a 3s timeout.
            # Running it synchronously here would stall the START of port
            # scanning for up to 3 full seconds on any target that filters ICMP
            # -- which is common. Run it in the background instead: it races
            # against the actual port scan (which usually takes as long or
            # longer anyway) rather than blocking it.
            os_ttl_thread = threading.Thread(target=self.detect_os_ttl_guess, daemon=True)
            os_ttl_thread.start()
        scan_type = "SYN" if self.config.syn_mode else "TCP Connect"
        if self.config.udp:
            scan_type += " + UDP probes"
        if display:
            console.print(Panel(
                f"[bold green]Target:[/bold green] {escape(self.target_host)}\n"
                f"[bold green]Addresses:[/bold green] {len(self.addresses)}\n"
                f"[bold green]Scan:[/bold green] {scan_type}\n"
                f"[bold green]Workers:[/bold green] {self.max_threads} | [bold green]Jobs:[/bold green] {len(scan_jobs)}",
                title="[bold cyan]M-Recon v" + V15_VERSION + "[/bold cyan]", expand=False
            ))

        def _run_jobs() -> None:
            progress_ctx = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) if display else None
            if progress_ctx is None:
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    self._execute_scan_batches(executor, scan_jobs, None, None)
            else:
                with progress_ctx as progress:
                    task_id = progress.add_task("[cyan]Scanning...", total=len(scan_jobs))
                    with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                        self._execute_scan_batches(executor, scan_jobs, progress, task_id)

        _run_jobs()
        self.fingerprint_pool.shutdown(wait=True)
        if os_ttl_thread is not None:
            # By now the actual port scan has already taken however long it
            # took, so the ping thread has usually long finished. Cap any
            # remaining wait to 0.5s (vs. the ping subprocess's own up-to-3s
            # timeout) so a very fast scan against an ICMP-filtered target
            # still doesn't pay the full blocking cost.
            os_ttl_thread.join(timeout=0.5)
        if self.cache:
            # Guarantee anything written since the last debounced disk save
            # (see FingerprintCache.put) actually lands on disk before we exit.
            self.cache.flush()
        self.stats.completed = len(scan_jobs)
        duration = round(time.monotonic() - scan_start, 2)
        report = self.build_report(ports, scan_type, duration)
        if display:
            render_scan_results(report, mode="compact")
        return report

    def _execute_scan_batches(self, executor: ThreadPoolExecutor, scan_jobs: list[tuple], progress=None, task_id=None) -> None:
        batch_size = max(1, self.max_threads)
        for start_idx in range(0, len(scan_jobs), batch_size):
            self.pause_event.wait()
            if self.stop_event.is_set():
                break
            batch = scan_jobs[start_idx:start_idx + batch_size]
            futures = []
            for family, ip, port, proto in batch:
                if self.stop_event.is_set():
                    break
                if proto == "udp":
                    futures.append(executor.submit(self.scan_udp, ip, port))
                elif self.config.syn_mode:
                    futures.append(executor.submit(self.scan_tcp_syn, family, ip, port))
                else:
                    futures.append(executor.submit(self.scan_tcp_connect, family, ip, port))
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    self.stats.inc("errors")
                    if progress is None:
                        # Background mode: keep stdout quiet to protect the interactive prompt.
                        logging.getLogger("mrecon").error("Worker error: %s", exc)
                    else:
                        console.print(f"[yellow][!] Worker error: {escape(str(exc))}[/yellow]")
                if progress is not None and task_id is not None:
                    progress.advance(task_id)

    def build_report(self, ports: list[int], scan_type: str, duration: float) -> dict:
        results = [asdict(x) for x in sorted(self.results, key=lambda r: (r.target_ip, r.port, r.protocol))]
        return {
            "tool": "M-Recon",
            "version": V15_VERSION,
            "target": self.target_host,
            "addresses": [{"family": self.family_label(f), "ip": ip} for f, ip in self.addresses],
            "os_guess": self.os_info,
            "scan_type": scan_type,
            "profile": self.config.profile,
            "workers": self.max_threads,
            "fingerprint_workers": self.fingerprint_workers,
            "rate_limit_per_sec": self.config.max_requests_per_second,
            "ports_requested": ports,
            "udp_probes": sorted(p for p in ports if p in UDP_PROBES) if self.config.udp else [],
            "stats": {
                "scheduled": self.stats.scheduled,
                "completed": self.stats.completed,
                "open_tcp": self.stats.open_tcp,
                "udp_responding": self.stats.udp_responding,
                "udp_no_response": self.stats.udp_no_response,
                "udp_errors": self.stats.udp_errors,
                "fingerprinted": self.stats.fingerprinted,
                "errors": self.stats.errors,
            },
            "dependencies": {"scapy": SCAPY_AVAILABLE, "cryptography": CRYPTO_AVAILABLE},
            "duration_sec": duration,
            "cache": {"enabled": bool(self.cache), "file": str(self.cache.path) if self.cache else None, "ttl_sec": self.config.cache_ttl_sec},
            "connection_failures": dict(self.connection_failures),
            "results": results,
        }

    def print_results(self) -> None:
        report = self.build_report([], "SYN" if self.config.syn_mode else "TCP Connect", 0.0)
        render_scan_results(report, mode="compact")

    def write_json(self, path: str, report: dict) -> None:
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    def write_csv(self, path: str, report: dict) -> None:
        fields = [
            "port", "protocol", "state", "target_ip", "address_family", "hostname", "service", "version", "banner",
            "confidence", "evidence", "tls", "tls_version", "tls_cipher", "cert_subject", "cert_issuer", "cert_san",
            "cert_not_before", "cert_not_after", "cert_sha256", "cert_days_left", "cert_verified", "cert_verify_note", "http_status", "http_server", "http_title",
            "http_content_type", "http_location", "waf_provider", "waf_confidence", "risk_level", "risk_score", "risk_reasons", "rtt_ms",
            "web_title", "web_technologies", "web_robots_found", "web_sitemap_found", "web_sitemap_type", "web_sitemap_urls", "web_sitemap_children", "web_security_txt_found",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for item in report["results"]:
                row = dict(item)
                tls_info = row.pop("tls_info", None) or {}
                row["tls"] = tls_info.get("present", False)
                row["tls_version"] = tls_info.get("version", "")
                row["tls_cipher"] = tls_info.get("cipher", "")
                row["cert_subject"] = tls_info.get("cert_subject", "")
                row["cert_issuer"] = tls_info.get("cert_issuer", "")
                row["cert_san"] = ";".join(tls_info.get("cert_san") or [])
                row["cert_not_before"] = tls_info.get("cert_not_before", "")
                row["cert_not_after"] = tls_info.get("cert_not_after", "")
                row["cert_sha256"] = tls_info.get("cert_sha256", "")
                # .get(key, "") only falls back when the key is MISSING -- these
                # two are Optional[...] fields that are legitimately present
                # with value None (verify_cert not used / no cert seen), so an
                # explicit None-check is needed or the CSV ends up with the
                # literal string "None" instead of a blank cell.
                cdl = tls_info.get("cert_days_left")
                row["cert_days_left"] = "" if cdl is None else cdl
                cv = tls_info.get("cert_verified")
                row["cert_verified"] = "" if cv is None else cv
                row["cert_verify_note"] = tls_info.get("cert_verify_note", "")
                row["risk_reasons"] = ";".join(row.get("risk_reasons") or [])
                web = row.get("web") or {}
                row["web_title"] = web.get("title", "")
                row["web_technologies"] = ";".join(web.get("technologies") or [])
                row["web_robots_found"] = (web.get("robots_txt") or {}).get("found", False)
                row["web_sitemap_found"] = (web.get("sitemap_xml") or {}).get("found", False)
                row["web_sitemap_type"] = web.get("sitemap_type", "")
                row["web_sitemap_urls"] = web.get("sitemap_url_count", "")
                row["web_sitemap_children"] = web.get("sitemap_child_count", "")
                row["web_security_txt_found"] = (web.get("security_txt") or {}).get("found", False)
                writer.writerow({k: row.get(k, "") for k in fields})

    def write_html(self, path: str, report: dict) -> None:
        """Render a self-contained HTML dashboard (no CDN/external assets --
        this stays usable completely offline, matching the project's
        dependency-free style).

        Beyond the original flat results table, this adds: risk-level and
        TLS-issue summary cards computed from the actual results (not just
        raw open/UDP counts), a client-side search box, click-to-sort
        columns, and per-row expandable TLS/Certificate + Risk-reasons detail
        (SAN, issuer, validity window, SHA-256, and every scored exposure
        reason) that the previous version only exposed in the CLI 'detail'
        view -- not in the HTML report at all.
        """
        def esc(v):
            return html.escape(str(v if v is not None else ""))

        results = report["results"]
        risk_counts = Counter(str(r.get("risk_level") or "INFO") for r in results)
        tls_issue_count = 0
        waf_providers: set[str] = set()
        for r in results:
            tls_info = r.get("tls_info") or {}
            if tls_info.get("version") in {"TLSv1", "TLSv1.1"}:
                tls_issue_count += 1
            elif tls_info.get("cert_days_left") is not None and tls_info["cert_days_left"] < 0:
                tls_issue_count += 1
            elif tls_info.get("cert_verified") is False:
                tls_issue_count += 1
            if r.get("waf_provider"):
                waf_providers.add(str(r["waf_provider"]))

        rows = []
        for r in results:
            web = r.get("web") or {}
            tls_info = r.get("tls_info") or {}
            web_bits = []
            if web.get("http_status") is not None:
                if web.get("title"):
                    web_bits.append(esc(web["title"]))
                found = []
                if (web.get("robots_txt") or {}).get("found"):
                    found.append("robots.txt")
                if (web.get("sitemap_xml") or {}).get("found"):
                    if web.get("sitemap_type") == "sitemapindex":
                        found.append(f"sitemap.xml (index, {web.get('sitemap_child_count', 0)} child sitemaps)")
                    else:
                        found.append(f"sitemap.xml ({web.get('sitemap_url_count', 0)} URLs)")
                if (web.get("security_txt") or {}).get("found"):
                    found.append("security.txt")
                if found:
                    web_bits.append(", ".join(found))
                if web.get("technologies"):
                    web_bits.append(esc(", ".join(web["technologies"])))
            web_summary = "<br>".join(web_bits) if web_bits else "-"

            cert_bits = []
            if tls_info.get("present"):
                if tls_info.get("cert_subject"):
                    cert_bits.append(f"<div><span class='muted'>Subject</span> {esc(tls_info['cert_subject'])}</div>")
                if tls_info.get("cert_issuer"):
                    cert_bits.append(f"<div><span class='muted'>Issuer</span> {esc(tls_info['cert_issuer'])}</div>")
                if tls_info.get("cert_san"):
                    cert_bits.append(f"<div><span class='muted'>SAN</span> {esc(', '.join(tls_info['cert_san']))}</div>")
                if tls_info.get("cert_not_before") or tls_info.get("cert_not_after"):
                    days_left = tls_info.get("cert_days_left")
                    days_left_note = f" ({days_left}d left)" if days_left is not None else ""
                    cert_bits.append(
                        f"<div><span class='muted'>Valid</span> {esc(tls_info.get('cert_not_before', ''))} &rarr; "
                        f"{esc(tls_info.get('cert_not_after', ''))}{esc(days_left_note)}</div>"
                    )
                if tls_info.get("cert_sha256"):
                    cert_bits.append(f"<div><span class='muted'>SHA-256</span> <code>{esc(tls_info['cert_sha256'][:24])}&hellip;</code></div>")
                if tls_info.get("cert_verified") is not None:
                    verdict = "verified" if tls_info["cert_verified"] else "NOT TRUSTED"
                    cert_bits.append(f"<div><span class='muted'>Trust</span> {esc(verdict)} &mdash; {esc(tls_info.get('cert_verify_note', ''))}</div>")
            cert_detail = (
                f"<details><summary>{esc(tls_info.get('version') or 'TLS')}</summary>{''.join(cert_bits)}</details>"
                if tls_info.get("present") else "-"
            )

            reasons = r.get("risk_reasons") or []
            risk_detail = (
                f"<details><summary>{esc(r.get('risk_level', 'INFO'))} ({r.get('risk_score', 0)})</summary>"
                + "".join(f"<div>{esc(reason)}</div>" for reason in reasons)
                + "</details>"
            ) if reasons else esc(r.get("risk_level", "INFO"))

            risk_level = str(r.get("risk_level") or "INFO")
            risk_class = {"MEDIUM": "risk-medium", "LOW": "risk-low"}.get(risk_level, "risk-info")
            rows.append(
                f"<tr class='{risk_class}' data-search='{esc(' '.join(str(x) for x in (r.get('target_ip'), r.get('port'), r.get('service'), r.get('version'), r.get('banner'), r.get('waf_provider'), risk_level)).lower())}'>"
                f"<td data-sort='{esc(r['target_ip'])}'>{esc(r['target_ip'])}</td>"
                f"<td data-sort='{esc(r['protocol'])}'>{esc(r['protocol'])}</td>"
                f"<td data-sort='{int(r['port'])}'>{esc(r['port'])}</td>"
                f"<td data-sort='{esc(r['service'])}'>{esc(r['service'])}</td>"
                f"<td>{esc(r['version'] or r['banner'])}</td>"
                f"<td>{cert_detail}</td>"
                f"<td data-sort='{esc(r['waf_provider'])}'>{esc(r['waf_provider']) or '-'}</td>"
                f"<td data-sort='{int(r.get('risk_score', 0))}'>{risk_detail}</td>"
                f"<td data-sort='{esc(r['confidence'])}'>{esc(r['confidence'])}</td>"
                f"<td>{web_summary}</td>"
                "</tr>"
            )

        risk_cards = "".join(
            f"<div class='card risk-{level.lower()}'><div class='muted'>{esc(level)}</div><strong>{risk_counts.get(level, 0)}</strong></div>"
            for level in ("MEDIUM", "LOW", "INFO")
        )

        style = (
            "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e7ecff;padding:28px}"
            "main{max-width:1500px;margin:auto}"
            ".muted{color:#9aa7c2;font-size:12px}"
            ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}"
            ".card{background:#121a2d;border:1px solid #263555;border-radius:12px;padding:14px}"
            ".card.risk-medium{border-color:#ef4444}.card.risk-low{border-color:#f59e0b}.card.risk-info{border-color:#263555}"
            "table{width:100%;border-collapse:collapse;background:#121a2d}"
            "th,td{padding:10px;border-bottom:1px solid #263555;text-align:left;font-size:13px;vertical-align:top}"
            "th{color:#a9b8d8;cursor:pointer;user-select:none;white-space:nowrap}"
            "th:hover{color:#fff}"
            "th.sorted::after{content:' \\25BE'}"
            "code{background:#17213a;padding:3px 6px;border-radius:6px}"
            "tr.risk-medium td:nth-child(8){color:#fca5a5}"
            "tr.risk-low td:nth-child(8){color:#fcd34d}"
            "details{cursor:pointer}"
            "details>div{margin-top:4px;font-size:12px;color:#c7d0ea}"
            "#search{width:100%;max-width:420px;padding:9px 12px;border-radius:8px;border:1px solid #263555;"
            "background:#121a2d;color:#e7ecff;margin-bottom:14px;font-size:13px}"
            "#search::placeholder{color:#6b7aa0}"
        )
        script = (
            "const q=document.getElementById('search');"
            "if(q){q.addEventListener('input',()=>{"
            "const v=q.value.toLowerCase();"
            "document.querySelectorAll('#results tbody tr').forEach(tr=>{"
            "tr.style.display=(tr.dataset.search||'').includes(v)?'':'none';});});}"
            "document.querySelectorAll('#results th[data-col]').forEach((th,idx)=>{"
            "th.addEventListener('click',()=>{"
            "const tbody=document.querySelector('#results tbody');"
            "const rows=Array.from(tbody.querySelectorAll('tr'));"
            "const asc=th.dataset.dir!=='asc';"
            "document.querySelectorAll('#results th').forEach(h=>h.classList.remove('sorted'));"
            "th.classList.add('sorted');th.dataset.dir=asc?'asc':'desc';"
            "rows.sort((a,b)=>{"
            "const ca=a.children[idx],cb=b.children[idx];"
            "const va=ca.dataset.sort??ca.textContent;const vb=cb.dataset.sort??cb.textContent;"
            "const na=parseFloat(va),nb=parseFloat(vb);"
            "let cmp;"
            "if(!isNaN(na)&&!isNaN(nb)&&String(na)===va.trim()&&String(nb)===vb.trim()){cmp=na-nb;}"
            "else{cmp=va.localeCompare(vb);}"
            "return asc?cmp:-cmp;});"
            "rows.forEach(r=>tbody.appendChild(r));});});"
        )

        doc = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>M-Recon v{esc(report['version'])}</title><style>{style}</style></head><body><main>"
            f"<h1>M-Recon v{esc(report['version'])}</h1>"
            f"<div class='muted'>Target: <code>{esc(report['target'])}</code> &middot; "
            f"Scan type: {esc(report.get('scan_type', ''))} &middot; Profile: {esc(report.get('profile', ''))} &middot; "
            f"Duration: {esc(report.get('duration_sec', 0))}s</div>"
            "<div class='grid'>"
            f"<div class='card'><div class='muted'>TCP open</div><strong>{report['stats']['open_tcp']}</strong></div>"
            f"<div class='card'><div class='muted'>UDP responding</div><strong>{report['stats']['udp_responding']}</strong></div>"
            f"<div class='card'><div class='muted'>Jobs</div><strong>{report['stats']['scheduled']}</strong></div>"
            f"<div class='card'><div class='muted'>OS guess</div><strong>{esc(report['os_guess'].get('guess'))}</strong></div>"
            f"<div class='card'><div class='muted'>TLS issues</div><strong>{tls_issue_count}</strong></div>"
            f"<div class='card'><div class='muted'>WAF/CDN providers</div><strong>{len(waf_providers)}</strong></div>"
            f"{risk_cards}"
            "</div>"
            "<h2>Results</h2>"
            "<input id='search' type='search' placeholder='Filter by IP, port, service, banner, WAF, risk level...'>"
            "<table id='results'><thead><tr>"
            "<th data-col>IP</th><th data-col>Proto</th><th data-col>Port</th><th data-col>Service</th>"
            "<th>Version / Banner</th><th>TLS / Certificate</th><th data-col>WAF/CDN hint</th>"
            "<th data-col>Risk (score)</th><th data-col>Confidence</th><th>Web Recon</th>"
            "</tr></thead><tbody>"
            f"{''.join(rows) or '<tr><td colspan=\"10\">No responding services</td></tr>'}"
            "</tbody></table>"
            f"<script>{script}</script>"
            "</main></body></html>"
        )
        Path(path).write_text(doc, encoding="utf-8")


def build_default_registry() -> ProbeRegistry:
    """Wire up the built-in protocol probes.

    This is the single place port->protocol coverage is extended. To add a
    new protocol: write a `probe_xxx(self, sock, port) -> ServiceResult`
    method on MReconScanner (see the ones above for the expected shape --
    confidence="high" only on real protocol evidence, "medium"/no evidence
    otherwise) and register it here with the ports it should be tried on.
    Nothing in the scanning/dispatch path (`_auto_probe_service`,
    `fingerprint`) needs to change, and no `if port == ...:` branch needs to
    be added there -- that is the point of routing every protocol through
    this registry instead.
    """
    registry = ProbeRegistry()
    registry.register(Probe("ssh", {22}, MReconScanner.probe_ssh, 10))
    registry.register(Probe("http", DEFAULT_HTTP_PORTS, lambda s, sock, p: s.probe_http(sock, p, tls=False), 20))
    registry.register(Probe("https", DEFAULT_HTTPS_PORTS, lambda s, sock, p: s.probe_http(sock, p, tls=True), 20))
    registry.register(Probe("text", {21, 25, 110, 143}, MReconScanner.probe_text, 30))
    registry.register(Probe("mysql", {3306}, MReconScanner.probe_mysql, 40))
    registry.register(Probe("redis", {6379}, MReconScanner.probe_redis, 41))
    registry.register(Probe("memcached", {11211}, MReconScanner.probe_memcached, 42))
    registry.register(Probe("postgresql", {5432}, MReconScanner.probe_postgres, 43))
    registry.register(Probe("mongodb", {27017, 27018, 27019}, MReconScanner.probe_mongodb, 44))
    registry.register(Probe("amqp", {5672}, MReconScanner.probe_amqp, 45))
    registry.register(Probe("vnc", {5900, 5901, 5902}, MReconScanner.probe_vnc, 46))
    registry.register(Probe("rdp", {3389}, MReconScanner.probe_rdp, 47))
    return registry


def load_plugins(registry: ProbeRegistry, directory: Optional[str]) -> list[str]:
    loaded = []
    if not directory or not Path(directory).is_dir():
        return loaded
    for file in sorted(Path(directory).glob("*.py")):
        if file.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"mrecon_plugin_{file.stem}", file)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            register = getattr(module, "register", None)
            if callable(register):
                register(registry)
                loaded.append(file.name)
        except Exception as exc:
            console.print(f"[yellow][!] Plugin load failed: {escape(str(exc))}[/yellow]")
    return loaded


def parse_ports(port_str: str) -> list[int]:
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not all(x.strip().isdigit() for x in bounds):
                raise ValueError(f"Invalid port range: {part}")
            start, end = map(int, [bounds[0].strip(), bounds[1].strip()])
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Port range out of bounds: {part}")
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit() or not 1 <= int(part) <= 65535:
                raise ValueError(f"Invalid port: {part}")
            ports.add(int(part))
    if not ports:
        raise ValueError("No valid ports were provided")
    return sorted(ports)


def load_targets(value: str) -> list[str]:
    path = Path(value)
    if not path.is_file():
        raise ValueError(f"Targets file not found: {value}")
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip() and not x.startswith("#")]


def expand_target_spec(spec: str, max_hosts: int = 4096) -> list[str]:
    """Expand @file / CIDR / IP-range target specs into a list of hosts.

    IMPORTANT: parsing failures (spec is not a CIDR/range, e.g. a plain hostname)
    fall through to `[spec]`, but a *successfully parsed* CIDR/range that exceeds
    `max_hosts` must raise, not be silently discarded as "unparseable". These two
    failure modes were previously funneled through the same except-ValueError,
    which swallowed the max_hosts guard entirely.
    """
    if spec.startswith("@"):
        return load_targets(spec[1:])

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            net = None
        if net is not None:
            hosts = [str(x) for x in net.hosts()] or [str(net.network_address)]
            if len(hosts) > max_hosts:
                raise ValueError(f"CIDR expands to {len(hosts)} hosts; limit is {max_hosts}")
            return hosts

    # Explicit IPv4/IPv6 range, e.g. 192.168.1.10-20 or 192.168.1.10-192.168.1.20
    if "-" in spec and not spec.startswith("http"):
        left, right = [x.strip() for x in spec.split("-", 1)]
        try:
            start = ipaddress.ip_address(left)
            end = ipaddress.ip_address(right if "." in right or ":" in right else f"{'.'.join(left.split('.')[:-1])}.{right}")
        except ValueError:
            start = end = None
        if start is not None and end is not None:
            if start.version != end.version or int(end) < int(start):
                raise ValueError("Invalid address range")
            count = int(end) - int(start) + 1
            if count > max_hosts:
                raise ValueError(f"Range expands to {count} hosts; limit is {max_hosts}")
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]

    return [spec]


def load_config(path: Optional[str]) -> tuple[ScanConfig, set[str]]:
    """Load a JSON/TOML config file.

    Returns (config, keys_present_in_file). Only `keys_present_in_file` should be
    copied onto a live ScanConfig by the caller -- copying every field of a fresh
    ScanConfig() would reset any field the file didn't mention back to its
    dataclass default, silently wiping out CLI flags or session settings applied
    around it.
    """
    if not path:
        return ScanConfig(), set()
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"Config file not found: {path}")
    if p.suffix.lower() == ".toml":
        if tomllib is None:
            raise ValueError("TOML requires Python 3.11+")
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    else:
        data = json.loads(p.read_text(encoding="utf-8"))
    cfg = ScanConfig()
    present: set[str] = set()
    for key, value in data.items():
        if key in {"lock", "explicit_fields"}:
            continue
        if hasattr(cfg, key):
            setattr(cfg, key, value)
            present.add(key)
    return cfg, present


def save_report(path: str, scanner: MReconScanner, report: dict, announce: bool = True) -> None:
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        scanner.write_csv(path, report)
    elif ext in {".html", ".htm"}:
        scanner.write_html(path, report)
    else:
        scanner.write_json(path, report)
    if announce:
        console.print(f"[bold blue][+] Report saved to: {escape(path)}[/bold blue]")


def confirm_large_scan(total_jobs: int, threshold: int) -> bool:
    if total_jobs <= threshold:
        return True
    console.print(f"[bold yellow][!] Planned probe jobs: {total_jobs}. Continue?[/bold yellow]")
    return console.input("[y/N]: ").strip().lower() in {"y", "yes"}


PORT_ALIASES = {
    "web": "80,443,3000,5000,8000,8001,8008,8080,8081,8443,8888,9443",
    "top": "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5672,5900,6379,8080,8443,9200,11211,27017",
}


def _parse_port_value(spec: str) -> list[int]:
    value = spec.strip().lower()
    if value == "all":
        return list(range(1, 65536))
    value = PORT_ALIASES.get(value, value)
    return parse_ports(value)


def _auto_tune(cfg: ScanConfig, jobs: int, profile: str = "balanced", explicit: Optional[set[str]] = None) -> ScanConfig:
    """Auto-tune only fields that were not explicitly requested by the user/config."""
    jobs = max(1, int(jobs))
    explicit = explicit or set()

    # Select a profile automatically when none was explicitly chosen.
    if "profile" not in explicit:
        if jobs >= 15000:
            profile = "fast"
        elif jobs >= 5000:
            profile = "balanced"
        else:
            profile = "balanced"
    else:
        profile = profile if profile in {"fast", "balanced", "deep"} else "balanced"

    # The user-facing defaults remain conservative; only explicitly requested
    # values bypass tuning. UDP/SYN/TLS/HTTP modes are deliberately not
    # auto-enabled because they change scan semantics rather than performance.
    if "workers" not in explicit:
        if profile == "fast":
            cfg.workers = min(max(32, int(jobs ** 0.5 * 6)), 96)
        elif profile == "deep":
            cfg.workers = min(max(64, int(jobs ** 0.5 * 10)), 160)
        else:
            cfg.workers = min(max(24, int(jobs ** 0.5 * 8)), 128)

    if "fingerprint_workers" not in explicit:
        if profile == "fast":
            cfg.fingerprint_workers = min(max(8, cfg.workers // 4), 16)
        elif profile == "deep":
            cfg.fingerprint_workers = min(max(16, cfg.workers // 3), 48)
        else:
            cfg.fingerprint_workers = min(max(8, cfg.workers // 4), 32)

    if "banner_timeout" not in explicit:
        if profile == "fast":
            cfg.banner_timeout = 0.8
        elif profile == "deep":
            cfg.banner_timeout = max(1.5, cfg.banner_timeout)
        else:
            cfg.banner_timeout = max(1.0, cfg.banner_timeout)

    if "max_http_bytes" not in explicit and profile == "deep":
        cfg.max_http_bytes = max(cfg.max_http_bytes, 131072)

    if "max_requests_per_second" not in explicit:
        if profile == "fast":
            cfg.max_requests_per_second = 220.0
        elif profile == "deep":
            cfg.max_requests_per_second = 140.0
        else:
            cfg.max_requests_per_second = 180.0

    cfg.profile = profile
    cfg.explicit_fields = set(explicit)
    return cfg


def _render_port_detail_sections(rows: list[dict]) -> None:
    """One integrated 'DETAILS' panel per port that has more to say than the
    overview table's single row can show -- TLS facts and/or a Web Recon
    result, together, not as two disjoint tables. A port with neither (a
    plain SSH or MySQL port, say) gets no panel at all: the overview row
    already said everything there is to say about it.

    Evidence-first throughout, matching the tool's overall philosophy: a
    resource is shown as FOUND with its status/size/what-was-in-it, never a
    bare boolean.
    """
    for item in sorted(rows, key=lambda r: (r.get("target_ip", ""), int(r.get("port", 0)))):
        tls_info = item.get("tls_info") or {}
        web = item.get("web")
        has_tls = bool(tls_info.get("present"))
        has_web = bool(web and web.get("http_status") is not None)
        if not has_tls and not has_web:
            continue

        target_label = f"{item.get('hostname') or item.get('target_ip', '')}:{item.get('port', '')}"
        table = Table(title=f"DETAILS - {escape(target_label)}", header_style="bold blue")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Service", escape(f"{item.get('service', '')} ({item.get('confidence', '')} confidence)"))

        if has_tls:
            table.add_row("-- TLS --", "")
            table.add_row("Version", escape(str(tls_info.get("version", ""))))
            if tls_info.get("cipher"):
                table.add_row("Cipher", escape(str(tls_info["cipher"])))
            if tls_info.get("cert_subject"):
                table.add_row("Cert subject", escape(str(tls_info["cert_subject"])))
            if tls_info.get("cert_issuer"):
                table.add_row("Cert issuer", escape(str(tls_info["cert_issuer"])))
            if tls_info.get("cert_san"):
                table.add_row("Cert SAN", escape(", ".join(tls_info["cert_san"])))
            if tls_info.get("cert_days_left") is not None:
                table.add_row("Cert expires in", escape(f"{tls_info['cert_days_left']} days"))
            if tls_info.get("cert_verified") is not None:
                verdict = "VERIFIED" if tls_info["cert_verified"] else "NOT TRUSTED"
                table.add_row("Cert trust", escape(f"{verdict} -- {tls_info.get('cert_verify_note', '')}"))

        if has_web:
            table.add_row("-- WEB RECON --", "")
            table.add_row("HTTP", escape(str(web.get("http_status", ""))))
            if web.get("title"):
                table.add_row("Title", escape(str(web["title"])))
            if web.get("server"):
                table.add_row("Server", escape(str(web["server"])))
            if web.get("powered_by"):
                table.add_row("Powered-By", escape(str(web["powered_by"])))
            if web.get("redirect_chain"):
                table.add_row("Redirects", escape(" | ".join(web["redirect_chain"])))
                table.add_row("Final URL", escape(str(web.get("final_url", ""))))
            if web.get("technologies"):
                table.add_row("Technologies", escape(", ".join(web["technologies"])))

            def _resource_row(label: str, res: Optional[dict]) -> None:
                if not res:
                    table.add_row(label, "NOT FOUND")
                    return
                if res.get("found"):
                    table.add_row(label, f"FOUND (status {res.get('status')}, {res.get('size', 0)} bytes)")
                    for ev in res.get("evidence", []):
                        table.add_row("", escape(f"  {ev}"))
                else:
                    status = res.get("status")
                    table.add_row(label, f"NOT FOUND (status {status})" if status is not None else "NOT FOUND")

            table.add_row("Resources", "")
            _resource_row("robots.txt", web.get("robots_txt"))
            _resource_row("sitemap.xml", web.get("sitemap_xml"))
            _resource_row("security.txt", web.get("security_txt"))

            if web.get("evidence"):
                table.add_row("Evidence", "")
                for ev in web["evidence"]:
                    table.add_row("", escape(f"  {ev}"))

        console.print(table)


def render_scan_results(report: dict, mode: str = "compact") -> None:
    """Single official results renderer for CLI and interactive shell.

    mode='compact' shows the findings table plus the statistical footer.
    mode='summary' shows only the statistical footer.
    """
    mode = mode.lower().strip()
    rows = report.get("results", [])
    if mode not in {"compact", "summary"}:
        mode = "compact"

    if mode == "compact":
        if not rows:
            console.print("[bold red][!] No responding services discovered.[/bold red]")
            failures = report.get("connection_failures", {}) or {}
            if failures:
                table = Table(title="Connection Diagnostics", header_style="bold yellow")
                table.add_column("Result")
                table.add_column("Count", justify="right")
                table.add_column("Meaning")
                meanings = {
                    "10061": "Connection refused — nothing is listening on that port.",
                    "10060": "Connection timed out — firewall/filtering or service not reachable.",
                    "10013": "Permission/access denied on the local socket.",
                    "111": "Connection refused (POSIX).",
                    "110": "Connection timed out (POSIX).",
                }
                for code, count in sorted(failures.items(), key=lambda x: (-x[1], x[0])):
                    table.add_row(str(code), str(count), meanings.get(str(code), "Socket connection failed; verify target/port and local listener."))
                console.print(table)
        else:
            table = Table(title=f"M-Recon Results - {escape(report.get('target', 'N/A'))}", header_style="bold magenta")
            for col in ["IP", "P", "PR", "ST", "S", "V", "L", "W", "R", "C"]:
                table.add_column(col)
            for item in sorted(rows, key=lambda r: (r.get("target_ip", ""), int(r.get("port", 0)), r.get("protocol", ""))):
                state = str(item.get("state", ""))
                state_style = {"OPEN": "bold green", "OPEN (response)": "bold green", "NO RESPONSE": "yellow", "ERROR": "bold red"}.get(state, "white")
                state_short = {"OPEN": "O", "OPEN (response)": "O", "NO RESPONSE": "NR", "ERROR": "ER"}.get(state, state[:2].upper())
                proto = str(item.get("protocol", "" )).lower()
                proto_short = {"tcp": "T", "udp": "U", "http": "H", "tls/http": "HL", "ssh": "SH", "mysql": "MY", "redis": "RD", "memcached": "MC"}.get(proto, proto[:2].upper())
                evidence = str(item.get("version") or item.get("banner") or item.get("evidence") or "")
                table.add_row(
                    str(item.get("target_ip", "")), str(item.get("port", "")), proto_short, f"[{state_style}]{state_short}[/]",
                    str(item.get("service", ""))[:16], escape(evidence[:45]),
                    str((item.get("tls_info") or {}).get("version") or ("Y" if (item.get("tls_info") or {}).get("present") else "-")),
                    str(item.get("waf_provider") or "-")[:12], str(item.get("risk_level") or "INFO")[:2],
                    str(item.get("confidence") or "low")[:1].upper(),
                )
            console.print(table)
            _render_port_detail_sections(rows)

    if mode in {"compact", "summary"}:
        stats = report.get("stats", {}) or {}
        summary = Table(title="Summary", header_style="bold cyan")
        summary.add_column("M")
        summary.add_column("N", justify="right")
        summary.add_row("TO", str(stats.get("open_tcp", 0)))
        summary.add_row("UR", str(stats.get("udp_responding", 0)))
        summary.add_row("UN", str(stats.get("udp_no_response", 0)))
        summary.add_row("UE", str(stats.get("udp_errors", 0)))
        summary.add_row("FP", str(stats.get("fingerprinted", 0)))
        console.print(summary)
        console.print("[dim]Legend: P=Port PR=Proto ST=State S=Service V=Ver/Evidence L=TLS W=WAF R=Risk C=Conf | T=TCP U=UDP H=HTTP HL=TLS/HTTP NR=NoReply ER=Error O=Open[/dim]")


def print_banner() -> None:
    console.print(BANNER)
    console.print(Panel(
        "[bold green]Terminal-only session[/bold green]\n"
        "Type [bold cyan]-h[/bold cyan] for help.\n"
        "Auto mode is the default; advanced controls are opt-in.",
        title="[bold cyan]M-Recon v" + V15_VERSION + "[/bold cyan]",
        expand=False,
        border_style="cyan",
    ))


def print_help() -> None:
    """Single place that prints HELP_TEXT so both entry points stay in sync.

    HELP_TEXT contains literal '[ports]' / '[N]' placeholders that are not
    Rich markup. Printing it with markup enabled makes Rich try to parse
    those brackets as style tags -- best case they silently disappear from
    the output, worst case Rich raises. markup=False prints the text as-is.
    """
    console.print(HELP_TEXT, markup=False)


def print_status() -> None:
    table = Table(title="M-Recon Runtime", header_style="bold magenta")
    table.add_column("C")
    table.add_column("ST")
    table.add_column("V")
    table.add_row("UI", "OK", "Rich/TUI")
    table.add_row("TCP", "OK", "Connect + SYN opt-in")
    table.add_row("UDP", "AUTO", "Protocol probes opt-in")
    table.add_row("HTTP", "AUTO", "Evidence-driven")
    table.add_row("TLS", "AUTO", "Evidence-driven")
    table.add_row("DNS", "AUTO", "Reverse DNS")
    table.add_row("SC", "AUTO", f"Scapy={SCAPY_STATE}; socket={SCAPY_SOCKET_NAME or 'none'}")
    table.add_row("CR", "OK", f"cryptography={CRYPTO_AVAILABLE}")
    table.add_row("PY", "OK", platform.python_version())
    console.print(table)




def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"M-Recon v{V15_VERSION}")
    # Positional target/ports keep the everyday CLI short: scan <target> <ports>.
    p.add_argument("target", nargs="?", help="Hostname, IP, CIDR, range, or @targets.txt")
    p.add_argument("ports_pos", nargs="?", help="Ports: 80,443 / 1-1024 / web / top / all")
    p.add_argument("--target", dest="target_opt", help=argparse.SUPPRESS)
    p.add_argument("-p", "--ports", dest="ports_opt", default=None, help=argparse.SUPPRESS)
    p.add_argument("-w", "--workers", dest="workers", type=int, default=None)
    p.add_argument("-t", "--timeout", dest="timeout", type=float, default=None)
    p.add_argument("-r", "--rate", dest="rate", type=float, default=None)
    p.add_argument("-fw", "--fingerprint-workers", dest="fingerprint_workers", type=int, default=None)
    p.add_argument("-b", "--banner-timeout", dest="banner_timeout", type=float, default=None)
    p.add_argument("-m", "--max-http-bytes", dest="max_http_bytes", type=int, default=None)
    p.add_argument("-o", "--output", default=None)
    p.add_argument("-cf", "--config", default=None)
    p.add_argument("-pl", "--plugins-dir", default=None)
    p.add_argument("-U", "--udp", action="store_true")
    p.add_argument("-S", "-s", "--syn", dest="syn", action="store_true")
    p.add_argument("-F", "-f", "--fragment", dest="fragment", action="store_true")
    p.add_argument("-q", dest="profile", action="store_const", const="fast")
    p.add_argument("-d", dest="profile_deep", action="store_true")
    p.add_argument("--profile", choices=["fast", "balanced", "deep"], default=None, dest="profile_long")
    p.add_argument("--skip-ping", action="store_true")
    p.add_argument("--verify-cert", action="store_true", help="Verify TLS certificates against the system trust store (additive check; does not block cert data collection)")
    p.add_argument("--no-web-recon", action="store_true", help="Disable the automatic Web Recon layer that triggers on confirmed HTTP/HTTPS ports")
    p.add_argument("-V", "--version", action="version", version=f"M-Recon {V15_VERSION}")
    return p


def _normalize_cli_target(args) -> str:
    target = getattr(args, "target", None) or getattr(args, "target_opt", None)
    if not target:
        raise ValueError("Target is required. Use: <target> [ports] ...")
    args.target = target
    ports = getattr(args, "ports_pos", None) or getattr(args, "ports_opt", None) or "1-1024"
    args.ports = ports
    return target


def run_scan(args) -> int:
    global LAST_REPORT, LAST_SCANNER, LAST_SCANNERS_BY_IP
    LAST_SCANNERS_BY_IP = {}
    # normalize the profile flag aliases (-q / -d / --profile) onto args.profile
    if getattr(args, "profile_long", None) is not None: args.profile = args.profile_long
    _normalize_cli_target(args)
    if getattr(args, "profile_deep", False): args.profile = "deep"
    if getattr(args, "version", False):
        console.print(f"M-Recon {V15_VERSION}"); return 0

    cfg = _clone_config(SESSION_CONFIG)
    # Config file first (only the keys it actually defines), so CLI flags below
    # always win over it, and it never resets untouched fields to hard defaults.
    config_explicit: set[str] = set()
    if args.config:
        cfg_file, config_explicit = load_config(args.config)
        for k in config_explicit:
            setattr(cfg, k, getattr(cfg_file, k))
    if args.workers is not None: cfg.workers = args.workers
    if args.timeout is not None: cfg.timeout = args.timeout
    if args.rate is not None: cfg.max_requests_per_second = args.rate
    if args.fingerprint_workers is not None: cfg.fingerprint_workers = args.fingerprint_workers
    if args.banner_timeout is not None: cfg.banner_timeout = args.banner_timeout
    if args.max_http_bytes is not None: cfg.max_http_bytes = args.max_http_bytes
    if args.udp: cfg.udp = True
    if args.syn: cfg.syn_mode = True
    if args.fragment: cfg.fragment = True
    if args.profile: cfg.profile = args.profile
    if args.plugins_dir: cfg.plugins_dir = args.plugins_dir
    if getattr(args, "skip_ping", False): cfg.skip_ping = True
    if getattr(args, "verify_cert", False): cfg.verify_cert = True
    if getattr(args, "no_web_recon", False): cfg.web_recon = False
    ports = _parse_port_value(args.ports)
    targets = expand_target_spec(args.target, cfg.max_hosts)
    jobs = len(targets) * len(ports) + (len(targets) * sum(1 for p in ports if p in UDP_PROBES) if cfg.udp else 0)
    explicit = set(SESSION_EXPLICIT_FIELDS) | config_explicit
    if args.workers is not None: explicit.add("workers")
    if args.timeout is not None: explicit.add("timeout")
    if args.rate is not None: explicit.add("max_requests_per_second")
    if args.fingerprint_workers is not None: explicit.add("fingerprint_workers")
    if args.banner_timeout is not None: explicit.add("banner_timeout")
    if args.max_http_bytes is not None: explicit.add("max_http_bytes")
    if args.profile is not None: explicit.add("profile")
    _auto_tune(cfg, jobs, cfg.profile, explicit)
    cfg.auto_mode = not bool(explicit)
    if not confirm_large_scan(jobs, cfg.large_scan_threshold): return 0

    registry = build_default_registry(); load_plugins(registry, cfg.plugins_dir)
    output = args.output
    reports = []
    for target in targets:
        scanner = MReconScanner(target, cfg, registry)
        report = scanner.run(ports, None, display=True)
        reports.append(report)
        LAST_SCANNER = scanner
        for _, ip_addr in scanner.addresses:
            LAST_SCANNERS_BY_IP[ip_addr] = scanner
        if output:
            path = output
            if len(targets) > 1:
                stem, ext = os.path.splitext(output); safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("._") or "target"; path = f"{stem}_{safe}{ext}"
            save_report(path, scanner, report)
    LAST_REPORT = _aggregate_reports(reports, args.target) if len(reports) > 1 else (reports[0] if reports else None)
    console.print("[bold green][+] Scan complete.[/bold green]")
    if getattr(args, "status_after", False):
        print_status()
    return 0


def build_cli_parser() -> argparse.ArgumentParser:
    return build_parser()


def local_selftest(port: int = 8080) -> None:
    table = Table(title="M-Recon Self-Test", header_style="bold cyan")
    table.add_column("K"); table.add_column("ST"); table.add_column("D")
    checks = []
    checks.append(("PY", True, platform.python_version()))
    checks.append(("RI", True, "Rich (required)"))
    scapy_ok = _ensure_scapy()
    checks.append(("SC", scapy_ok, f"Scapy ({SCAPY_STATE}; optional SYN mode)"))
    checks.append(("CR", CRYPTO_AVAILABLE, "cryptography (optional; certificate parsing)"))
    try:
        socket.getaddrinfo("localhost", None); checks.append(("DNS", True, "resolver"))
    except OSError as exc:
        checks.append(("DNS", False, str(exc)))
    try:
        ctx = ssl.create_default_context(); checks.append(("TLS", True, "stdlib"))
    except Exception as exc:
        checks.append(("TLS", False, str(exc)))
    try:
        family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM); s.close(); checks.append(("IP6", family == socket.AF_INET6, "socket"))
    except OSError:
        checks.append(("IP6", False, "unavailable"))
    start = time.monotonic()
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=1.0):
            checks.append(("TCP", True, f"127.0.0.1:{port} {(time.monotonic()-start)*1000:.1f}ms"))
    except OSError as exc:
        checks.append(("TCP", False, f"127.0.0.1:{port} {type(exc).__name__}"))
    for k, ok, desc in checks:
        table.add_row(k, "OK" if ok else "--", str(desc))
    console.print(table)


LAST_REPORT: Optional[dict] = None
LAST_SCANNER: Optional[MReconScanner] = None
LAST_SCANNERS_BY_IP: dict[str, MReconScanner] = {}
SESSION_CONFIG = ScanConfig()
SESSION_EXPLICIT_FIELDS: set[str] = set()

BANNER = r"""[bold cyan]
███╗   ███╗     ██████╗  ███████╗ ██████╗ ███╗   ██╗
████╗ ████║    ██╔════╝  ██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║    ██║       █████╗  ██║   ██║██╔██╗ ██║
██║╚██╔╝██║    ██║       ██╔══╝  ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║    ╚██████╗  ███████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝     ╚═════╝  ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
                    M - R E C O N
[/bold cyan]"""

HELP_TEXT = f"""M-Recon v{V15_VERSION}

Start
  ms

Scan
  scan <target> [ports]
  scan <target> [ports] -U   add UDP probes
  scan <target> [ports] -S   SYN mode
  scan <target> [ports] -F   SYN fragment mode
  scan <target> [ports] -d   deep
  scan <target> [ports] -q   fast

Options
  -w N    workers
  -t N    timeout
  -r N    rate/sec
  -fw N   fingerprint workers
  -b N    banner timeout
  -m N    HTTP bytes
  -o F    JSON/CSV/HTML report (only when explicitly supplied)
  -cf F   config
  -pl D   plugins

Web
  tr- F    content discovery wordlist (after a completed scan)

Shell
  -h        help
  -V        version
  -st       status
  -c        clear
  cfg       auto/manual policy
  cfg set K V  set a runtime default
  detail N  full details for port N
  tst [N]   self-test
  -x        exit

Examples
  scan 127.0.0.1
  scan 127.0.0.1 80,443
  scan 127.0.0.1 web
  scan 127.0.0.1 1-1024 -U
  scan 127.0.0.1 1-1024 -U -d -w 64 -r 100
"""


def print_config_summary() -> None:
    """Show the current session configuration and explicitly overridden fields."""
    table = Table(title="M-Recon Session Config", header_style="bold cyan")
    table.add_column("Key")
    table.add_column("Value")
    fields = [
        "workers", "timeout", "banner_timeout", "fingerprint_workers",
        "max_requests_per_second", "max_http_bytes", "profile",
        "syn_mode", "fragment", "udp", "skip_ping", "http", "tls",
        "reverse_dns", "verify_cert", "web_recon", "plugins_dir", "cache", "cache_ttl_sec",
    ]
    for key in fields:
        table.add_row(key, str(getattr(SESSION_CONFIG, key)))
    explicit = ", ".join(sorted(SESSION_EXPLICIT_FIELDS)) or "none"
    console.print(table)
    console.print(f"[dim]Explicit overrides: {escape(explicit)}[/dim]")


def _clone_config(cfg: ScanConfig) -> ScanConfig:
    values = {}
    for k in ScanConfig.__dataclass_fields__:
        if k == "lock":
            continue
        value = getattr(cfg, k)
        if k == "explicit_fields":
            value = set(value)
        values[k] = value
    return ScanConfig(**values)

def _bool_cast(value: str) -> bool:
    v = value.strip().lower()
    if v in {"1", "true", "yes", "on", "y"}:
        return True
    if v in {"0", "false", "no", "off", "n"}:
        return False
    raise ValueError(f"Expected a boolean (true/false), got: {value}")


def _profile_cast(value: str) -> str:
    v = value.strip().lower()
    if v not in {"fast", "balanced", "deep"}:
        raise ValueError("profile must be one of: fast, balanced, deep")
    return v


def _apply_cfg_override(cfg: ScanConfig, key: str, value: str) -> None:
    mapping = {
        "w": ("workers", int),
        "t": ("timeout", float),
        "r": ("max_requests_per_second", float),
        "fw": ("fingerprint_workers", int),
        "b": ("banner_timeout", float),
        "m": ("max_http_bytes", int),
        "pl": ("plugins_dir", str),
        "profile": ("profile", _profile_cast),
        "udp": ("udp", _bool_cast),
        "syn": ("syn_mode", _bool_cast),
        "fragment": ("fragment", _bool_cast),
        "skip_ping": ("skip_ping", _bool_cast),
        "skip-ping": ("skip_ping", _bool_cast),
        "http": ("http", _bool_cast),
        "tls": ("tls", _bool_cast),
        "reverse_dns": ("reverse_dns", _bool_cast),
        "verify_cert": ("verify_cert", _bool_cast),
        "web_recon": ("web_recon", _bool_cast),
        "cache": ("cache", _bool_cast),
    }
    if key not in mapping:
        raise ValueError(f"Unknown cfg key: {key}")
    attr, cast = mapping[key]
    value_cast = cast(value)
    setattr(cfg, attr, value_cast)
    SESSION_EXPLICIT_FIELDS.add(attr)
    cfg.explicit_fields.add(attr)

def _aggregate_reports(reports: list[dict], target_spec: str) -> dict:
    """Merge per-target scan reports into one session report."""
    if not reports:
        return {"tool": "M-Recon", "version": V15_VERSION, "target": target_spec, "results": [], "stats": {}}
    merged = dict(reports[0])
    merged["target"] = target_spec
    merged["addresses"] = [addr for r in reports for addr in r.get("addresses", [])]
    merged["results"] = [row for r in reports for row in r.get("results", [])]
    stats_keys = ("scheduled", "completed", "open_tcp", "udp_responding", "udp_no_response", "udp_errors", "fingerprinted", "errors")
    merged["stats"] = {k: sum(int(r.get("stats", {}).get(k, 0)) for r in reports) for k in stats_keys}
    failures = {}
    for r in reports:
        for code, count in (r.get("connection_failures", {}) or {}).items():
            failures[str(code)] = failures.get(str(code), 0) + int(count)
    merged["connection_failures"] = failures
    merged["duration_sec"] = round(sum(float(r.get("duration_sec", 0.0)) for r in reports), 2)
    merged["targets_scanned"] = len(reports)
    merged["target_reports"] = [{"target": r.get("target"), "duration_sec": r.get("duration_sec", 0.0), "stats": r.get("stats", {})} for r in reports]
    return merged


def _shell_args(parts: list[str]) -> argparse.Namespace:
    if not parts or parts[0].lower() != "scan":
        raise SystemExit("Use: scan <target> <ports> [options]")
    if len(parts) < 2:
        raise SystemExit("scan requires a target")
    target = parts[1]
    idx = 2
    ports = "1-1024"
    if idx < len(parts) and not parts[idx].startswith("-"):
        ports = parts[idx]
        idx += 1
    args = build_parser().parse_args([target, ports])
    _normalize_cli_target(args)

    value_map = {
        "-w": ("workers", int), "--workers": ("workers", int),
        "-t": ("timeout", float), "--timeout": ("timeout", float),
        "-r": ("rate", float), "--rate": ("rate", float),
        "-fw": ("fingerprint_workers", int), "--fingerprint-workers": ("fingerprint_workers", int),
        "-b": ("banner_timeout", float), "--banner-timeout": ("banner_timeout", float),
        "-m": ("max_http_bytes", int), "--max-http-bytes": ("max_http_bytes", int),
        "-o": ("output", str), "--output": ("output", str),
        "-cf": ("config", str), "--config": ("config", str),
        "-pl": ("plugins_dir", str), "--plugins-dir": ("plugins_dir", str),
        "--profile": ("profile", _profile_cast),
    }
    flag_map = {
        "-U": ("udp", True), "--udp": ("udp", True),
        "-S": ("syn", True), "-s": ("syn", True), "--syn": ("syn", True),
        "-F": ("fragment", True), "-f": ("fragment", True), "--fragment": ("fragment", True),
        "-d": ("profile", "deep"), "--deep": ("profile", "deep"),
        "-q": ("profile", "fast"), "--fast": ("profile", "fast"),
        "--skip-ping": ("skip_ping", True),
        "--verify-cert": ("verify_cert", True),
        "--no-web-recon": ("no_web_recon", True),
        "-st": ("status_after", True),
        "--status": ("status_after", True),
    }
    i = 0
    while i < len(parts[idx:]):
        rest = parts[idx:]
        tok = rest[i]
        if tok in flag_map:
            attr, value = flag_map[tok]
            setattr(args, attr, value)
            i += 1
            continue
        if tok in value_map:
            if i + 1 >= len(rest):
                raise SystemExit(f"{tok} needs a value")
            attr, cast = value_map[tok]
            try:
                setattr(args, attr, cast(rest[i + 1]))
            except ValueError:
                raise SystemExit(f"Invalid value for {tok}: {rest[i + 1]}")
            i += 2
            continue
        raise SystemExit(f"Unknown option: {tok}")
    return args


def _run_tr_command(wordlist_path: str) -> None:
    """Run metadata-only Web Content Discovery against confirmed web services
    from the last completed scan. No report is written automatically.
    """
    if not LAST_REPORT:
        console.print("[yellow]No completed scan yet. Run a scan first.[/yellow]")
        return
    path = Path(wordlist_path).expanduser()
    if not path.is_file():
        console.print(f"[red]Wordlist not found: {escape(str(path))}[/red]")
        return
    try:
        if path.stat().st_size > WEB_DISCOVERY_MAX_WORDLIST_BYTES:
            console.print(f"[red]Wordlist is too large; limit is {WEB_DISCOVERY_MAX_WORDLIST_BYTES // (1024 * 1024)} MiB.[/red]")
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        console.print(f"[red]Could not read wordlist: {escape(str(exc))}[/red]")
        return

    rows = [r for r in LAST_REPORT.get("results", []) if r.get("state") == "OPEN" and r.get("service") in {"http", "https"} and (r.get("web") or {}).get("http_status") is not None]
    if not rows:
        console.print("[yellow]No confirmed HTTP/HTTPS services in the last scan.[/yellow]")
        return

    console.print(f"[bold cyan]WEB DISCOVERY[/bold cyan]  [dim]{escape(path.name)}[/dim]")
    total_found = 0
    for row in rows:
        ip = str(row.get("target_ip", ""))
        scanner = LAST_SCANNERS_BY_IP.get(ip) or LAST_SCANNER
        if scanner is None:
            continue
        port = int(row.get("port", 0))
        tls = bool((row.get("tls_info") or {}).get("present")) or row.get("service") == "https"
        result = scanner.discover_web_content(ip, port, tls, lines)
        found = result.get("found", [])
        if not found:
            continue
        total_found += len(found)
        table = Table(title=f"WEB DISCOVERY - {escape(ip)}:{port}", header_style="bold blue")
        table.add_column("ST", justify="right")
        table.add_column("PATH")
        table.add_column("SIZE", justify="right")
        table.add_column("TYPE")
        table.add_column("REDIRECT")
        for item in found:
            status = int(item["status"])
            style = "bold green" if status in {200, 204, 206} else "yellow" if status in {301, 302, 307, 308} else "bold magenta"
            table.add_row(f"[{style}]{status}[/]", escape(item["path"]), str(item["size"]), escape(item["content_type"] or "-"), escape(item["location"] or "-"))
        console.print(table)

    if total_found:
        console.print(f"[bold green][+] {total_found} relevant path(s) found.[/bold green]")
    else:
        console.print("[dim]No relevant paths found.[/dim]")


def _print_detail(report: Optional[dict], port: int) -> None:
    """Print full stored details for one port from the last completed report.

    Network/service/HTTP basics go in the summary table here; TLS facts and
    Web Recon (if either ran for this port) are shown together in ONE
    integrated panel via _render_port_detail_sections, rather than repeating
    TLS/cert fields in two different tables.
    """
    if not report:
        console.print("[yellow]No completed scan report in this session.[/yellow]")
        return
    rows = [r for r in report.get("results", []) if int(r.get("port", -1)) == int(port)]
    if not rows:
        console.print(f"[yellow]No result for port {port} in the last report.[/yellow]")
        return
    for r in rows:
        table = Table(title=f"M-Recon Detail - {r.get('target_ip', 'N/A')}:{r.get('port', port)}", header_style="bold cyan")
        table.add_column("Field")
        table.add_column("Value")
        tls_info = r.get("tls_info") or {}
        web = r.get("web")
        fields = [
            ("Protocol", r.get("protocol", "")),
            ("State", r.get("state", "")),
            ("Address family", r.get("address_family", "")),
            ("Hostname", r.get("hostname", "")),
            ("Service", r.get("service", "")),
            ("Version", r.get("version", "")),
            ("Banner", r.get("banner", "")),
            ("Confidence", r.get("confidence", "")),
            ("Evidence", r.get("evidence", "")),
            ("TLS", tls_info.get("present", False)),
            ("HTTP status", r.get("http_status", "")),
            ("HTTP server", r.get("http_server", "")),
            ("HTTP title", r.get("http_title", "")),
            ("HTTP content type", r.get("http_content_type", "")),
            ("HTTP location", r.get("http_location", "")),
            ("WAF/CDN", r.get("waf_provider", "")),
            ("WAF confidence", r.get("waf_confidence", "")),
            ("Risk", r.get("risk_level", "")),
            ("Risk score", r.get("risk_score", 0)),
            ("Risk reasons", "; ".join(r.get("risk_reasons") or [])),
            ("RTT ms", r.get("rtt_ms", "")),
        ]
        if tls_info.get("present"):
            fields.append(("TLS / Certificate", "see DETAILS panel below"))
        if web:
            fields.append(("Web Recon", "see DETAILS panel below" if web.get("http_status") is not None else "attempted, no HTTP response"))
        for key, value in fields:
            # These values come from the scanned target (banners, TLS/cert
            # fields, HTTP titles, etc.) and are not trusted input. escape()
            # keeps a literal '[...]' from a remote banner/title from being
            # parsed as Rich markup.
            table.add_row(key, escape(str(value)) if value not in (None, "") else "-")
        console.print(table)
        _render_port_detail_sections([r])


def interactive_shell() -> int:
    print_banner()
    while True:
        try:
            line = console.input("[bold red]mrecon> [/bold red]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Exiting...[/yellow]")
            return 0
        if not line:
            continue
        tokens = shlex.split(line)
        command = tokens[0]
        low = command.lower()
        if low in {"-x", "exit", "quit"}:
            return 0
        if low in {"ms", "-ms"}:
            console.print("[cyan]M-Recon interactive shell is already running.[/cyan]")
            continue
        if low in {"-h", "help"}:
            print_help()
            continue
        if command == "-V" or low == "version":
            console.print(f"[bold cyan]M-Recon v{V15_VERSION}[/bold cyan]")
            continue
        if low in {"-st", "status"}:
            print_status()
            if LAST_REPORT:
                console.print(f"[green]Last scan: {escape(str(LAST_REPORT.get('target', 'N/A')))} | results={len(LAST_REPORT.get('results', []))}[/green]")
            else:
                console.print("[dim]No completed scan yet.[/dim]")
            continue
        if low in {"-c", "clear"}:
            console.clear(); print_banner(); continue
        if low in {"-rt", "reports"}:
            if LAST_REPORT:
                render_scan_results(LAST_REPORT, mode="compact")
            else:
                console.print("[cyan]No report in this session.[/cyan]")
            continue
        if low in {"tr-", "-tr", "tr"}:
            if len(tokens) != 2:
                console.print("[yellow]Usage: tr- <wordlist>[/yellow]")
            else:
                _run_tr_command(tokens[1])
            continue
        if low in {"cfg", "config"}:
            if len(tokens) >= 4 and tokens[1].lower() == "set":
                try:
                    _apply_cfg_override(SESSION_CONFIG, tokens[2].lstrip("-"), tokens[3])
                    console.print(f"[green]cfg {escape(tokens[2])}={escape(tokens[3])}[/green]")
                except Exception as exc:
                    console.print(f"[red]cfg error: {escape(str(exc))}[/red]")
            else:
                print_config_summary()
            continue
        if low == "detail":
            if len(tokens) != 2 or not tokens[1].isdigit() or LAST_REPORT is None:
                console.print("[yellow]Usage: detail <port> (after a scan)[/yellow]")
            else:
                _print_detail(LAST_REPORT, int(tokens[1]))
            continue
        if low in {"-tst", "tst", "selftest"}:
            port = int(tokens[1]) if len(tokens) == 2 and tokens[1].isdigit() else 8080
            local_selftest(port)
            continue
        if low in {"-pl", "plugins"}:
            console.print("[cyan]Use -pl <dir> during scan to load probes.[/cyan]")
            continue
        if low != "scan":
            console.print("[bold red][!] Unknown command. Use -h.[/bold red]")
            continue
        try:
            args = _shell_args(tokens)
            # Foreground by design: the scan owns the prompt until completion,
            # then the complete results table is printed immediately. No implicit saving.
            run_scan(args)
        except SystemExit as exc:
            console.print(f"[bold red][!] {escape(str(exc))}[/bold red]")
        except Exception as exc:
            console.print(f"[bold red][!] {escape(str(exc))}[/bold red]")


def main() -> int:
    if "--version" in sys.argv[1:]:
        console.print(f"M-Recon {V15_VERSION}")
        return 0
    parser = build_cli_parser()
    try:
        args = parser.parse_args()
        return run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Interrupted.[/yellow]")
        return 130
    except Exception as exc:
        console.print(f"[bold red][!] Fatal error: {escape(str(exc))}[/bold red]")
        return 1


def entrypoint() -> int:
    raw = sys.argv[1:]
    if not raw:
        return interactive_shell()
    if raw and raw[0] in {"ms", "-ms"}:
        rest = raw[1:]
        if not rest:
            return interactive_shell()
        if rest[0] in {"-V", "--version"}:
            console.print(f"M-Recon {V15_VERSION}")
            return 0
        if rest[0] == "-h":
            print_help()
            return 0
        sys.argv = [sys.argv[0], *rest]
        return main()
    if "--shell" in raw:
        return interactive_shell()
    if "--cli" in raw:
        sys.argv = [sys.argv[0], *[x for x in raw if x != "--cli"]]
        return main()
    return main()


if __name__ == "__main__":
    raise SystemExit(entrypoint())