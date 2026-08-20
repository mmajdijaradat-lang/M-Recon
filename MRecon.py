#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M-Recon v14.3
Protocol-aware reconnaissance scanner for authorized security testing.

Focus:
- IPv4 + IPv6 TCP scanning
- Optional TCP SYN state probes (Scapy; IPv4, elevated privileges)
- Optional UDP probes with explicit states
- Adaptive timeouts + bounded concurrency + rate limiting
- Protocol-aware service/version fingerprinting
- HTTP + real TLS handshake on any TCP port
- WAF/CDN provider hints with confidence, not hard claims
- Evidence-based exposure/risk scoring (not vulnerability claims)
- Reverse DNS
- JSON / CSV / HTML reporting
- TOML/JSON configuration
- External probe plugins
- Unit/integration-friendly architecture

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
import ssl
import subprocess
import sys
import threading
from collections import Counter
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
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
    print("[-] Missing dependency 'rich'. Install via: py -m pip install rich")
    raise SystemExit(1)

try:
    from scapy.all import IP, IPv6, TCP, sr1, sr, send, fragment, conf, L3RawSocket
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

console = Console()
USER_AGENT = "M-Recon/14.2"

DEFAULT_HTTP_PORTS = {80, 3000, 5000, 8000, 8001, 8008, 8080, 8081, 8888, 18080}
DEFAULT_HTTPS_PORTS = {443, 8443, 9443}
UDP_PROBES = {
    53: bytes.fromhex("0000010000010000000000000377777706676f6f676c6503636f6d0000010001"),
    123: b"\x1b" + b"\x00" * 47,
    161: bytes.fromhex("302602010104067075626c6963a019020400000000020100020100300b300906052b060102010101000500"),
}


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
    plugins_dir: Optional[str] = None
    output: Optional[str] = None
    large_scan_threshold: int = 5000


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
    http_status: Optional[int] = None
    http_server: str = ""
    http_title: str = ""
    http_content_type: str = ""
    http_location: str = ""
    waf_provider: str = ""
    waf_confidence: str = "low"
    risk_level: str = "INFO"
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class PortResult:
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
    tls: bool
    tls_version: str
    tls_cipher: str
    cert_subject: str
    cert_issuer: str
    cert_san: list[str]
    cert_not_before: str
    cert_not_after: str
    cert_sha256: str
    http_status: Optional[int]
    http_server: str
    http_title: str
    http_content_type: str
    http_location: str
    waf_provider: str
    waf_confidence: str
    risk_level: str
    risk_reasons: list[str]
    rtt_ms: float


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
                        result.cert_not_before = cert.not_valid_before_utc.isoformat()
                        result.cert_not_after = cert.not_valid_after_utc.isoformat()
                    else:
                        result.cert_not_before = cert.not_valid_before.isoformat()
                        result.cert_not_after = cert.not_valid_after.isoformat()
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


class MReconScanner:
    def __init__(self, target_host: str, config: Optional[ScanConfig] = None, registry: Optional[ProbeRegistry] = None):
        self.target_host = target_host
        self.config = config or ScanConfig()
        self.registry = registry or build_default_registry()
        self.max_threads = max(1, min(int(self.config.workers), 256))
        self.fingerprint_workers = max(1, min(int(self.config.fingerprint_workers), 64))
        self.timeout_manager = AdaptiveTimeoutManager(self.config.timeout)
        self.rate_limiter = RateLimiter(self.config.max_requests_per_second)
        self.banner_timeout = max(0.2, float(self.config.banner_timeout))
        self.stats = ScanStats()
        self.connection_failures = Counter()
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

    def connect(self, family: int, ip: str, port: int, timeout: float) -> socket.socket:
        self.rate_limiter.wait()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if family == socket.AF_INET6:
            sock.connect((ip, port, 0, 0))
        else:
            sock.connect((ip, port))
        return sock

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

    def assess_exposure(self, port: int, service: str, result: ServiceResult) -> tuple[str, list[str]]:
        reasons: list[str] = []
        level = "INFO"
        if port in {21, 23}:
            level = "MEDIUM"
            reasons.append("Cleartext administrative/service protocol exposed")
        if port == 80 and result.http_status is not None:
            level = "LOW"
            reasons.append("HTTP service is unencrypted")
        if port == 445 or service == "microsoft-ds":
            level = "MEDIUM"
            reasons.append("SMB service exposed")
        if service == "redis" and any("PONG" in x.upper() for x in result.evidence):
            level = "MEDIUM"
            reasons.append("Redis responded to unauthenticated PING; validate access controls separately")
        if result.tls and result.tls_version in {"TLSv1", "TLSv1.1"}:
            level = "MEDIUM"
            reasons.append(f"Legacy TLS protocol observed: {result.tls_version}")
        return level, reasons

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

    def probe_http(self, sock: socket.socket, port: int, tls: bool = False) -> ServiceResult:
        result = ServiceResult(service="https" if tls else "http", protocol="tls/http" if tls else "http", confidence="high", tls=tls)
        if tls:
            server_hostname = self.target_host if not self.target_host.replace(".", "").isdigit() else None
            sock, tls_info = TLSInspector.inspect(sock, server_hostname, self.banner_timeout)
            for key in ("tls_version", "tls_cipher", "cert_subject", "cert_issuer", "cert_not_before", "cert_not_after", "cert_sha256"):
                setattr(result, key, getattr(tls_info, key))
            result.cert_san = tls_info.cert_san
            result.evidence.extend(tls_info.evidence)
        host_header = self.target_host
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

    def fingerprint(self, family: int, ip: str, port: int) -> ServiceResult:
        sock = None
        try:
            sock = self.connect(family, ip, port, self.banner_timeout)
            for probe in self.registry.candidates(port):
                try:
                    return probe.handler(self, sock, port)
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = self.connect(family, ip, port, self.banner_timeout)

            if self.config.http:
                http = self.probe_http(sock, port, tls=False)
                if http.http_status is not None:
                    return http
            if self.config.tls:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                tls_http = self._try_http(family, ip, port, tls=True)
                if tls_http:
                    return tls_http
            return ServiceResult(service=self.service_from_port(port), protocol="tcp", confidence="low")
        except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
            return ServiceResult(service=self.service_from_port(port), protocol="tcp", confidence="low")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def append_tcp_open(self, family: int, ip: str, port: int, elapsed: float) -> None:
        self.rate_limiter.wait()
        fp = self.fingerprint(family, ip, port)
        self.stats.inc("fingerprinted")
        fp.risk_level, fp.risk_reasons = self.assess_exposure(port, fp.service, fp)
        item = PortResult(
            port=port, protocol=fp.protocol, state="OPEN", target_ip=ip,
            address_family=self.family_label(family), hostname=self.hostnames.get(ip, "N/A"),
            service=fp.service, version=fp.version, banner=fp.banner,
            confidence=fp.confidence, evidence="; ".join(fp.evidence),
            tls=fp.tls, tls_version=fp.tls_version, tls_cipher=fp.tls_cipher,
            cert_subject=fp.cert_subject, cert_issuer=fp.cert_issuer, cert_san=fp.cert_san,
            cert_not_before=fp.cert_not_before, cert_not_after=fp.cert_not_after,
            cert_sha256=fp.cert_sha256, http_status=fp.http_status,
            http_server=fp.http_server, http_title=fp.http_title,
            http_content_type=fp.http_content_type, http_location=fp.http_location,
            waf_provider=fp.waf_provider, waf_confidence=fp.waf_confidence,
            risk_level=fp.risk_level, risk_reasons=fp.risk_reasons,
            rtt_ms=round(elapsed * 1000, 2),
        )
        with self.lock:
            self.results.append(item)
        self.stats.inc("open_tcp")

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
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                self.append_tcp_open(family, ip, port, elapsed)
            else:
                self.connection_failures[str(code)] += 1
        except OSError as exc:
            self.connection_failures[type(exc).__name__] += 1
        except Exception as exc:
            self.connection_failures[type(exc).__name__] += 1
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def scan_tcp_syn(self, family: int, ip: str, port: int) -> None:
        if not SCAPY_AVAILABLE or family != socket.AF_INET:
            self.scan_tcp_connect(family, ip, port)
            return
        start = time.monotonic()
        timeout = self.timeout_manager.get_timeout()
        self.rate_limiter.wait()
        try:
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
        except (OSError, PermissionError):
            # Fall back to a normal connect scan for robustness.
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
            tls=False, tls_version="", tls_cipher="", cert_subject="", cert_issuer="", cert_san=[],
            cert_not_before="", cert_not_after="", cert_sha256="", http_status=None, http_server="",
            http_title="", http_content_type="", http_location="", waf_provider="", waf_confidence="low",
            risk_level="INFO", risk_reasons=risk_reasons, rtt_ms=round(elapsed * 1000, 2)
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
        if self.config.profile == "fast":
            self.config.banner_timeout = min(self.config.banner_timeout, 0.8)
            self.config.fingerprint_workers = min(self.config.fingerprint_workers, 16)
        elif self.config.profile == "deep":
            self.config.banner_timeout = max(self.config.banner_timeout, 2.0)
            self.config.fingerprint_workers = min(max(self.config.fingerprint_workers, 32), 64)
            self.config.max_http_bytes = max(self.config.max_http_bytes, 131072)

    def run(self, ports: list[int], output_file: Optional[str] = None) -> dict:
        if not self.addresses:
            return {}
        self.apply_profile()
        scan_start = time.monotonic()
        if self.config.syn_mode and SCAPY_AVAILABLE:
            try:
                conf.L3socket = L3RawSocket
            except Exception:
                pass
        scan_jobs = [(family, ip, port, "tcp") for family, ip in self.addresses for port in ports]
        if self.config.udp:
            udp_ports = [p for p in ports if p in UDP_PROBES]
            scan_jobs.extend((socket.AF_INET6 if ":" in ip else socket.AF_INET, ip, p, "udp") for _, ip in self.addresses for p in udp_ports)
        self.stats.scheduled = len(scan_jobs)
        if not self.config.skip_ping:
            self.detect_os_ttl_guess()
        scan_type = "SYN" if self.config.syn_mode else "TCP Connect"
        if self.config.udp:
            scan_type += " + UDP probes"
        console.print(Panel(
            f"[bold green]Target:[/bold green] {escape(self.target_host)}\n"
            f"[bold green]Addresses:[/bold green] {len(self.addresses)}\n"
            f"[bold green]Scan:[/bold green] {scan_type}\n"
            f"[bold green]Workers:[/bold green] {self.max_threads} | [bold green]Jobs:[/bold green] {len(scan_jobs)}",
            title="[bold cyan]M-Recon v14.3[/bold cyan]", expand=False
        ))
        progress = None
        task_id = None
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=len(scan_jobs))
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for family, ip, port, proto in scan_jobs:
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
                        console.print(f"[yellow][!] Worker error: {escape(str(exc))}[/yellow]")
                    progress.advance(task_id)
        self.stats.completed = len(scan_jobs)
        duration = round(time.monotonic() - scan_start, 2)
        self.print_results()
        report = self.build_report(ports, scan_type, duration)
        if output_file:
            save_report(output_file, self, report)
        return report

    def build_report(self, ports: list[int], scan_type: str, duration: float) -> dict:
        results = [asdict(x) for x in sorted(self.results, key=lambda r: (r.target_ip, r.port, r.protocol))]
        return {
            "tool": "M-Recon",
            "version": "14.2",
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
            "results": results,
        }

    def print_results(self) -> None:
        if not self.results:
            console.print("[bold red][!] No responding services discovered.[/bold red]")
            if self.connection_failures:
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
                for code, count in sorted(self.connection_failures.items(), key=lambda x: (-x[1], x[0])):
                    table.add_row(code, str(count), meanings.get(code, "Socket connection failed; verify target/port and local listener."))
                console.print(table)
            return
        table = Table(title=f"M-Recon Results - {escape(self.target_host)}", header_style="bold magenta")
        # Compact terminal columns: every label is <= 2 characters.
        for col in ["IP", "P", "PR", "ST", "S", "V", "L", "W", "R", "C"]:
            table.add_column(col)
        for item in sorted(self.results, key=lambda r: (r.target_ip, r.port, r.protocol)):
            state_style = {"OPEN": "bold green", "OPEN (response)": "bold green", "NO RESPONSE": "yellow", "ERROR": "bold red"}.get(item.state, "white")
            state_short = {
                "OPEN": "O",
                "OPEN (response)": "O",
                "NO RESPONSE": "NR",
                "ERROR": "ER",
            }.get(item.state, item.state[:2].upper())
            state_text = f"[{state_style}]{state_short}[/]"
            proto_short = {"tcp": "T", "udp": "U", "http": "H", "tls/http": "HL", "ssh": "SH", "mysql": "MY", "redis": "RD", "memcached": "MC"}.get(item.protocol.lower(), item.protocol[:2].upper())
            evidence = item.version or item.banner or item.evidence
            table.add_row(
                item.target_ip, str(item.port), proto_short, state_text, item.service[:16],
                escape(evidence[:45]), item.tls_version or ("Y" if item.tls else "-"),
                item.waf_provider[:12] if item.waf_provider else "-", item.risk_level[:2], item.confidence[:1].upper(),
            )
        console.print(table)
        summary = Table(title="Summary", header_style="bold cyan")
        summary.add_column("M")
        summary.add_column("N", justify="right")
        summary.add_row("TO", str(self.stats.open_tcp))
        summary.add_row("UR", str(self.stats.udp_responding))
        summary.add_row("UN", str(self.stats.udp_no_response))
        summary.add_row("UE", str(self.stats.udp_errors))
        summary.add_row("FP", str(self.stats.fingerprinted))
        console.print(summary)
        console.print("[dim]Legend: P=Port PR=Proto ST=State S=Service V=Ver/Evidence L=TLS W=WAF R=Risk C=Conf | T=TCP U=UDP H=HTTP HL=TLS/HTTP NR=NoReply ER=Error O=Open[/dim]")

    def write_json(self, path: str, report: dict) -> None:
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    def write_csv(self, path: str, report: dict) -> None:
        fields = [
            "port", "protocol", "state", "target_ip", "address_family", "hostname", "service", "version", "banner",
            "confidence", "evidence", "tls", "tls_version", "tls_cipher", "cert_subject", "cert_issuer", "cert_san",
            "cert_not_before", "cert_not_after", "cert_sha256", "http_status", "http_server", "http_title",
            "http_content_type", "http_location", "waf_provider", "waf_confidence", "risk_level", "risk_reasons", "rtt_ms"
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for item in report["results"]:
                row = dict(item)
                row["cert_san"] = ";".join(row.get("cert_san") or [])
                row["risk_reasons"] = ";".join(row.get("risk_reasons") or [])
                writer.writerow({k: row.get(k, "") for k in fields})

    def write_html(self, path: str, report: dict) -> None:
        def esc(v):
            return html.escape(str(v if v is not None else ""))
        rows = []
        for r in report["results"]:
            rows.append(
                "<tr>"
                f"<td>{esc(r['target_ip'])}</td><td>{esc(r['protocol'])}</td><td>{esc(r['port'])}</td>"
                f"<td>{esc(r['service'])}</td><td>{esc(r['version'] or r['banner'])}</td>"
                f"<td>{esc(r['tls_version'] or ('yes' if r['tls'] else '-'))}</td>"
                f"<td>{esc(r['waf_provider'])}</td><td>{esc(r['risk_level'])}</td><td>{esc(r['confidence'])}</td>"
                "</tr>"
            )
        doc = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>M-Recon v{esc(report['version'])}</title><style>body{{font-family:system-ui;background:#0b1020;color:#e7ecff;padding:28px}}main{{max-width:1400px;margin:auto}}.muted{{color:#9aa7c2}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}}.card{{background:#121a2d;border:1px solid #263555;border-radius:12px;padding:14px}}table{{width:100%;border-collapse:collapse;background:#121a2d}}th,td{{padding:10px;border-bottom:1px solid #263555;text-align:left;font-size:13px}}th{{color:#a9b8d8}}code{{background:#17213a;padding:3px 6px;border-radius:6px}}</style></head><body><main><h1>M-Recon v{esc(report['version'])}</h1><div class='muted'>Target: <code>{esc(report['target'])}</code></div><div class='grid'><div class='card'><div class='muted'>TCP open</div><strong>{report['stats']['open_tcp']}</strong></div><div class='card'><div class='muted'>UDP responding</div><strong>{report['stats']['udp_responding']}</strong></div><div class='card'><div class='muted'>Jobs</div><strong>{report['stats']['scheduled']}</strong></div><div class='card'><div class='muted'>OS guess</div><strong>{esc(report['os_guess'].get('guess'))}</strong></div></div><h2>Results</h2><table><thead><tr><th>IP</th><th>Proto</th><th>Port</th><th>Service</th><th>Version / Banner</th><th>TLS</th><th>WAF/CDN hint</th><th>Risk</th><th>Confidence</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="9">No responding services</td></tr>'}</tbody></table></main></body></html>"""
        Path(path).write_text(doc, encoding="utf-8")


def build_default_registry() -> ProbeRegistry:
    registry = ProbeRegistry()
    registry.register(Probe("ssh", {22}, MReconScanner.probe_ssh, 10))
    registry.register(Probe("http", DEFAULT_HTTP_PORTS, lambda s, sock, p: s.probe_http(sock, p, tls=False), 20))
    registry.register(Probe("https", DEFAULT_HTTPS_PORTS, lambda s, sock, p: s.probe_http(sock, p, tls=True), 20))
    registry.register(Probe("text", {21, 25, 110, 143}, MReconScanner.probe_text, 30))
    registry.register(Probe("mysql", {3306}, MReconScanner.probe_mysql, 40))
    registry.register(Probe("redis", {6379}, MReconScanner.probe_redis, 41))
    registry.register(Probe("memcached", {11211}, MReconScanner.probe_memcached, 42))
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
    if spec.startswith("@"):
        return load_targets(spec[1:])
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(x) for x in net.hosts()]
            if len(hosts) > max_hosts:
                raise ValueError(f"CIDR expands to {len(hosts)} hosts; limit is {max_hosts}")
            return hosts
    except ValueError:
        pass
    # Explicit IPv4 range, e.g. 192.168.1.10-20 or 192.168.1.10-192.168.1.20
    if "-" in spec and not spec.startswith("http"):
        left, right = [x.strip() for x in spec.split("-", 1)]
        try:
            start = ipaddress.ip_address(left)
            end = ipaddress.ip_address(right if "." in right or ":" in right else f"{'.'.join(left.split('.')[:-1])}.{right}")
            if start.version != end.version or int(end) < int(start):
                raise ValueError("Invalid address range")
            count = int(end) - int(start) + 1
            if count > max_hosts:
                raise ValueError(f"Range expands to {count} hosts; limit is {max_hosts}")
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError:
            pass
    return [spec]


def load_config(path: Optional[str]) -> ScanConfig:
    if not path:
        return ScanConfig()
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
    for key, value in data.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    return cfg


def save_report(path: str, scanner: MReconScanner, report: dict) -> None:
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        scanner.write_csv(path, report)
    elif ext in {".html", ".htm"}:
        scanner.write_html(path, report)
    else:
        scanner.write_json(path, report)
    console.print(f"[bold blue][+] Report saved to: {escape(path)}[/bold blue]")


def confirm_large_scan(total_jobs: int, threshold: int) -> bool:
    if total_jobs <= threshold:
        return True
    console.print(f"[bold yellow][!] Planned probe jobs: {total_jobs}. Continue?[/bold yellow]")
    return console.input("[y/N]: ").strip().lower() in {"y", "yes"}


def run_scan(args) -> int:
    cfg = load_config(args.config)
    if args.workers is not None:
        cfg.workers = args.workers
    if args.timeout is not None:
        cfg.timeout = args.timeout
    if args.syn:
        cfg.syn_mode = True
    if args.fragment:
        cfg.fragment = True
    if args.udp:
        cfg.udp = True
    if args.skip_ping:
        cfg.skip_ping = True
    if args.profile is not None:
        cfg.profile = args.profile
    if args.rate is not None:
        cfg.max_requests_per_second = args.rate
    if args.fingerprint_workers is not None:
        cfg.fingerprint_workers = args.fingerprint_workers
    if args.banner_timeout is not None:
        cfg.banner_timeout = args.banner_timeout
    if args.max_http_bytes is not None:
        cfg.max_http_bytes = args.max_http_bytes
    if args.no_http:
        cfg.http = False
    if args.no_tls:
        cfg.tls = False
    if args.plugins_dir:
        cfg.plugins_dir = args.plugins_dir

    ports = parse_ports(args.ports)
    targets = expand_target_spec(args.target)
    # Worst-case scan jobs, including UDP protocol-aware probes.
    per_target = len(ports) + (sum(1 for p in ports if p in UDP_PROBES) if cfg.udp else 0)
    total_jobs = len(targets) * per_target
    if not confirm_large_scan(total_jobs, cfg.large_scan_threshold):
        console.print("[yellow][*] Cancelled.[/yellow]")
        return 0

    registry = build_default_registry()
    loaded = load_plugins(registry, cfg.plugins_dir)
    if loaded:
        console.print(f"[cyan][*] Loaded plugins: {', '.join(loaded)}[/cyan]")

    for target in targets:
        scanner = MReconScanner(target, cfg, registry)
        output = args.output or cfg.output
        if output and len(targets) > 1:
            stem, ext = os.path.splitext(output)
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("._") or "target"
            output = f"{stem}_{safe}{ext}"
        start = time.monotonic()
        report = scanner.run(ports, output)
        duration = round(time.monotonic() - start, 2)
        report["duration_sec"] = duration
        if output:
            save_report(output, scanner, report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="M-Recon v14.3")
    p.add_argument("-t", "--target", required=True, help="Hostname, IP, CIDR, IP range, or @targets.txt")
    p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-w", "--workers", type=int, default=None)
    p.add_argument("-T", "--timeout", type=float, default=None)
    p.add_argument("-s", "-sS", "--syn", action="store_true")
    p.add_argument("-f", "--fragment", action="store_true")
    p.add_argument("--udp", action="store_true")
    p.add_argument("--skip-ping", action="store_true")
    p.add_argument("--rate", type=float, default=None)
    p.add_argument("--fingerprint-workers", type=int, default=None)
    p.add_argument("--banner-timeout", type=float, default=None)
    p.add_argument("--max-http-bytes", type=int, default=None)
    p.add_argument("--no-http", action="store_true")
    p.add_argument("--no-tls", action="store_true")
    p.add_argument("--plugins-dir")
    p.add_argument("--config")
    p.add_argument("--profile", choices=["fast", "balanced", "deep"], default=None)
    p.add_argument("-o", "--output")
    p.add_argument("--version", action="version", version="M-Recon 14.3")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Interrupted.[/yellow]")
        return 130
    except Exception as exc:
        console.print(f"[bold red][!] Fatal error: {escape(str(exc))}[/bold red]")
        return 1





# -----------------------------------------------------------------------------
# M-Recon v14.3 Terminal UI
# Terminal/TUI only: Rich banner, panels, tables, progress, interactive shell.
# No desktop GUI dependencies are used.
# -----------------------------------------------------------------------------

BANNER = """[bold cyan]

███╗   ███╗███╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗
████╗ ████║████╗  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║██╔██╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╔╝██║██║╚██╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║ ╚████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

[/bold cyan][bold white]M-Recon v14.3 — Advanced Protocol-Aware Reconnaissance Suite[/bold white]
"""

HELP_TEXT = """
[bold cyan]M-Recon Terminal Commands[/bold cyan]

[bold]scan[/bold] -t <target> [options]
  Run a scan. The 'scan' prefix is optional.

[bold]Compact legend[/bold]
  T TCP | U UDP | H HTTP | L TLS | W WAF | R Risk | C Confidence | P Port
  O Open | NR No Response | ER Error | FP Fingerprint

[bold]Options[/bold]
  -t, --target <host>      Host/IP/CIDR/range or @targets.txt
  -p, --ports <spec>       e.g. 22,80,443,8000-8100 (default: 1-1024)
  -w, --workers <n>        Concurrent workers (default engine value: 100)
  -T, --timeout <sec>      Initial timeout
  -s, -sS, --syn           SYN probe (IPv4 + Scapy; falls back safely)
  -f, --fragment           Fragment SYN packets (implies SYN)
  --udp                    Enable protocol-aware UDP probes
  --skip-ping              Skip TTL-based OS guess
  --rate <n>               Max probe starts/sec (0 = unlimited)
  --fingerprint-workers <n>
                           Fingerprint worker ceiling
  --banner-timeout <sec>   Service probe timeout
  --max-http-bytes <n>     HTTP body/header read cap
  --no-http                Disable HTTP probing
  --no-tls                 Disable TLS probing
  --plugins-dir <dir>      Load external probe plugins
  --config <file>          TOML/JSON config
  --profile <fast|balanced|deep>
  -o, --output <file>      .json / .csv / .html report

[bold]Shell commands[/bold]
  [bold]help[/bold]       Show this help
  [bold]status[/bold]     Show runtime/dependency status
  [bold]clear[/bold]      Clear the terminal
  [bold]version[/bold]    Show version
  [bold]exit[/bold] / [bold]quit[/bold]

[bold]Examples[/bold]
  scan -t 127.0.0.1 -p 22,80,443
  scan -t 192.168.1.0/24 -p 1-1024 --profile balanced
  scan -t example.com -sS --udp --deep -o report.html
  scan -t @targets.txt -p 80,443 -o report.json
"""


def print_banner() -> None:
    console.print(BANNER)
    console.print(Panel(
        "[bold green]Terminal interface active[/bold green]\n"
        "Type [bold cyan]help[/bold cyan] for commands.\n"
        "Authorized testing only.",
        title="[bold cyan]Session[/bold cyan]",
        expand=False,
        border_style="cyan",
    ))


def print_status() -> None:
    table = Table(title="M-Recon Runtime Status", header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="white")
    table.add_row("Rich", "READY", "Terminal UI")
    table.add_row("Scapy", "AVAILABLE" if SCAPY_AVAILABLE else "NOT INSTALLED",
                  "SYN/fragment support" if SCAPY_AVAILABLE else "Connect scan fallback")
    table.add_row("Cryptography", "AVAILABLE" if CRYPTO_AVAILABLE else "OPTIONAL",
                  "Certificate parsing" if CRYPTO_AVAILABLE else "Certificate fingerprint only")
    table.add_row("Python", platform.python_version(), platform.platform())
    table.add_row("Engine", "M-Recon 14.3", "IPv4/IPv6, T/U, H/L, plugins, reports")
    console.print(table)


def build_cli_args(parts: list[str]) -> argparse.Namespace:
    if parts and parts[0].lower() in {"scan", "run", "mrecon", "ms", "mp"}:
        parts = parts[1:]
    return build_parser().parse_args(parts)


def local_selftest(port: int) -> None:
    target = ("127.0.0.1", port)
    console.print(Panel(f"Testing direct TCP connectivity to 127.0.0.1:{port}", title="M-Recon Self-Test", expand=False))
    start = time.monotonic()
    try:
        with socket.create_connection(target, timeout=2.0):
            elapsed = (time.monotonic() - start) * 1000
            console.print(f"[bold green][+] TCP CONNECT OK[/bold green] — {elapsed:.2f} ms")
    except OSError as exc:
        console.print(f"[bold red][-] TCP CONNECT FAILED[/bold red] — {type(exc).__name__}: {exc}")
        console.print("[yellow]Check the listener with: Test-NetConnection 127.0.0.1 -Port <port>[/yellow]")


def interactive_shell() -> int:
    print_banner()
    while True:
        try:
            line = console.input("[bold red]mrecon> [/bold red]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Exiting M-Recon...[/bold yellow]")
            return 0
        if not line:
            continue
        lowered = line.lower()
        if lowered in {"exit", "quit"}:
            console.print("[bold yellow]Exiting M-Recon Shell...[/bold yellow]")
            return 0
        if lowered == "help":
            console.print(HELP_TEXT)
            continue
        if lowered == "version":
            console.print("[bold cyan]M-Recon v14.3[/bold cyan]")
            continue
        if lowered == "status":
            print_status()
            continue
        if lowered == "clear":
            console.clear()
            print_banner()
            continue
        if lowered.startswith("selftest"):
            parts = shlex.split(line)
            if len(parts) != 2 or not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535):
                console.print("[yellow]Usage: selftest <port>[/yellow]")
            else:
                local_selftest(int(parts[1]))
            continue
        try:
            args = build_cli_args(shlex.split(line))
            run_scan(args)
        except SystemExit as exc:
            if exc.code not in (0, None):
                console.print("[bold red][!] Invalid command. Type 'help'.[/bold red]")
        except Exception as exc:
            console.print(f"[bold red][!] {escape(str(exc))}[/bold red]")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Interrupted.[/yellow]")
        return 130
    except Exception as exc:
        console.print(f"[bold red][!] Fatal error: {escape(str(exc))}[/bold red]")
        return 1


def entrypoint() -> int:
    # Default: full Rich terminal/TUI shell with banner.
    # CLI remains available whenever arguments are supplied or with --cli.
    raw = sys.argv[1:]
    if "--cli" in raw:
        raw.remove("--cli")
        sys.argv = [sys.argv[0], *raw]
        return main()
    if "--shell" in raw:
        # Explicit shell flag, even if extra shell-safe args are present.
        return interactive_shell()
    if not raw:
        return interactive_shell()
    return main()


if __name__ == "__main__":
    raise SystemExit(entrypoint())
