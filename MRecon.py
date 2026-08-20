#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M-Recon v15.4
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
import copy
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
USER_AGENT = "M-Recon/15.4"
V15_VERSION = "15.4"


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
    auto_mode: bool = True
    cache: bool = True
    cache_ttl_sec: int = 900
    cache_file: str = ".mrecon_cache.json"
    max_hosts: int = 4096


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
    cert_days_left: Optional[int]
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


class FingerprintCache:
    """Small TTL cache for service fingerprints; optional persistent JSON backing."""
    def __init__(self, path: str = ".mrecon_cache.json", ttl_sec: int = 900):
        self.path = Path(path)
        self.ttl_sec = max(0, int(ttl_sec))
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.is_file():
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.data = {}

    def _save(self) -> None:
        try:
            self.path.write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
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
        with self.lock:
            self.data[key] = {"ts": time.time(), "result": asdict(result)}
            self._save()


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
                        remaining = cert.not_valid_after_utc - __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    else:
                        result.cert_not_before = cert.not_valid_before.isoformat()
                        result.cert_not_after = cert.not_valid_after.isoformat()
                        remaining = cert.not_valid_after - __import__("datetime").datetime.utcnow()
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
        """Describe exposure, not vulnerabilities. Evidence changes the level conservatively."""
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2}
        level = "INFO"
        reasons: list[str] = []

        def raise_level(new_level: str, reason: str) -> None:
            nonlocal level
            if rank[new_level] > rank[level]:
                level = new_level
            reasons.append(reason)

        if port in {21, 23}:
            raise_level("MEDIUM", "Cleartext administrative/service protocol exposed")
        if port == 80 and result.http_status is not None:
            raise_level("LOW", "HTTP service is unencrypted")
        if port in {445, 139} or service == "microsoft-ds":
            raise_level("MEDIUM", "SMB-related service exposed")
        if port in {3389, 5900} and result.service != "unknown":
            raise_level("MEDIUM", "Remote access service exposed")
        if service == "redis" and any("PONG" in x.upper() for x in result.evidence):
            raise_level("MEDIUM", "Redis responded to PING; validate access controls separately")
        if service == "memcached" and result.version:
            raise_level("LOW", "Memcached service responded to a version probe")
        if result.tls and result.tls_version in {"TLSv1", "TLSv1.1"}:
            raise_level("MEDIUM", f"Legacy TLS protocol observed: {result.tls_version}")
        if result.cert_days_left is not None:
            if result.cert_days_left < 0:
                raise_level("MEDIUM", "TLS certificate appears expired")
            elif result.cert_days_left <= 30:
                raise_level("LOW", f"TLS certificate expires in {result.cert_days_left} days")
        if result.waf_provider:
            reasons.append(f"WAF/CDN hint: {result.waf_provider} ({result.waf_confidence})")
        if not reasons:
            reasons.append("No notable exposure pattern detected by built-in rules")
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

            candidates = self.registry.candidates(port)
            for probe in candidates:
                try:
                    if probe.name in {"http", "https"} and probe.name == "https":
                        continue
                    return probe.handler(self, sock, port)
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    try: sock.close()
                    except OSError: pass
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
                    if sock:
                        sock.close()
                    sock = self.connect(family, ip, port, self.banner_timeout)
                    tls = self.probe_http(sock, port, tls=True)
                    if tls.tls:
                        return tls
                except (socket.timeout, OSError, ssl.SSLError, ConnectionError):
                    pass

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
            cert_sha256=fp.cert_sha256, cert_days_left=fp.cert_days_left, http_status=fp.http_status,
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
            cert_not_before="", cert_not_after="", cert_sha256="", cert_days_left=None, http_status=None, http_server="",
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
            title="[bold cyan]M-Recon v" + V15_VERSION + "[/bold cyan]", expand=False
        ))
        progress = None
        task_id = None
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=len(scan_jobs))
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
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
                            console.print(f"[yellow][!] Worker error: {escape(str(exc))}[/yellow]")
                        progress.advance(task_id)
        self.stats.completed = len(scan_jobs)
        duration = round(time.monotonic() - scan_start, 2)
        self.print_results()
        report = self.build_report(ports, scan_type, duration)
        return report

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
            "cert_not_before", "cert_not_after", "cert_sha256", "cert_days_left", "http_status", "http_server", "http_title",
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


PORT_ALIASES = {
    "web": "80,443,3000,5000,8000,8001,8008,8080,8081,8443,8888,9443",
    "top": "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5900,6379,8080,8443,9200,11211",
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
    return cfg


def _print_results_compact(report: dict, port: Optional[int] = None) -> None:
    rows = report.get("results", [])
    if port is not None:
        rows = [r for r in rows if int(r.get("port", -1)) == port]
    if not rows:
        console.print("[yellow]No matching result.[/yellow]")
        return
    table = Table(title="M-Recon Detail" if port is not None else "M-Recon Results", header_style="bold magenta")
    for col in ("P", "PR", "ST", "S", "V", "L", "W", "R", "C"):
        table.add_column(col)
    for r in rows:
        proto = str(r.get("protocol", ""))
        if proto == "tcp": pr = "T"
        elif proto.startswith("udp"): pr = "U"
        elif proto == "http": pr = "H"
        elif "tls/http" in proto: pr = "HL"
        else: pr = proto[:2].upper()
        state = str(r.get("state", ""))
        st = "O" if "OPEN" in state else ("NR" if "NO RESPONSE" in state else ("ER" if "ERROR" in state else state[:3].upper()))
        version = str(r.get("version") or r.get("banner") or "")[:54]
        table.add_row(
            str(r.get("port", "")), pr, st, str(r.get("service", ""))[:14], version,
            str(r.get("tls_version") or ("yes" if r.get("tls") else "-")),
            str(r.get("waf_provider") or "-"), str(r.get("risk_level") or "INFO")[:2],
            str(r.get("confidence") or "low")[:1].upper(),
        )
    console.print(table)


def _print_summary(report: dict) -> None:
    stats = report.get("stats", {})
    table = Table(title="Summary", header_style="bold magenta")
    table.add_column("M")
    table.add_column("N", justify="right")
    mapping = [
        ("TO", stats.get("scheduled", 0)),
        ("O", stats.get("open_tcp", 0)),
        ("UR", stats.get("udp_responding", 0)),
        ("UN", sum(1 for r in report.get("results", []) if r.get("state") == "NO RESPONSE")),
        ("UE", sum(1 for r in report.get("results", []) if r.get("state") == "ERROR")),
        ("FP", stats.get("fingerprinted", 0)),
    ]
    for k, v in mapping:
        table.add_row(k, str(v))
    console.print(table)
    console.print("[dim]M=metric TO=jobs O=open UR=UDP reply UN=no reply UE=UDP error FP=fingerprints[/dim]")


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
    table.add_row("SC", "OK", f"Scapy={SCAPY_AVAILABLE}")
    table.add_row("CR", "OK", f"cryptography={CRYPTO_AVAILABLE}")
    table.add_row("PY", "OK", platform.python_version())
    console.print(table)




def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"M-Recon v{V15_VERSION}")
    # Positional target/ports keep the everyday CLI short: scan <target> [ports].
    p.add_argument("target", nargs="?", help="Hostname, IP, CIDR, range, or @targets.txt")
    p.add_argument("ports_pos", nargs="?", help="Ports: 80,443 / 1-1024 / web / top / all")
    p.add_argument("--target", dest="target_opt", help=argparse.SUPPRESS)
    p.add_argument("-p", "--ports", dest="ports_opt", default=None, help=argparse.SUPPRESS)
    p.add_argument("-w", dest="workers", type=int, default=None)
    p.add_argument("-t", "--timeout", dest="timeout", type=float, default=None)
    p.add_argument("-r", dest="rate", type=float, default=None)
    p.add_argument("-fw", dest="fingerprint_workers", type=int, default=None)
    p.add_argument("-b", dest="banner_timeout", type=float, default=None)
    p.add_argument("-m", dest="max_http_bytes", type=int, default=None)
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
    global LAST_REPORT, LAST_SCANNER
    # normalize hidden long aliases / profile flags
    if getattr(args, "workers_long", None) is not None: args.workers = args.workers_long
    if getattr(args, "fpw_long", None) is not None: args.fingerprint_workers = args.fpw_long
    if getattr(args, "b_long", None) is not None: args.banner_timeout = args.b_long
    if getattr(args, "m_long", None) is not None: args.max_http_bytes = args.m_long
    if getattr(args, "r_long", None) is not None: args.rate = args.r_long
    if getattr(args, "pl_long", None) is not None: args.plugins_dir = args.pl_long
    if getattr(args, "profile_long", None) is not None: args.profile = args.profile_long
    _normalize_cli_target(args)
    if getattr(args, "profile_deep", False): args.profile = "deep"
    if getattr(args, "version", False):
        console.print(f"M-Recon {V15_VERSION}"); return 0

    cfg = _clone_config(SESSION_CONFIG)
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
    if args.config:
        cfg_file = load_config(args.config)
        for k in ScanConfig.__dataclass_fields__:
            if k in {"lock"}: continue
            if hasattr(cfg_file, k): setattr(cfg, k, getattr(cfg_file, k))
    ports = _parse_port_value(args.ports)
    targets = expand_target_spec(args.target, cfg.max_hosts)
    jobs = len(targets) * len(ports) + (len(targets) * sum(1 for p in ports if p in UDP_PROBES) if cfg.udp else 0)
    explicit = set(SESSION_EXPLICIT_FIELDS)
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
    output = args.output or cfg.output
    for target in targets:
        scanner = MReconScanner(target, cfg, registry)
        report = scanner.run(ports, None)
        LAST_SCANNER = scanner; LAST_REPORT = report
        if output:
            path = output
            if len(targets) > 1:
                stem, ext = os.path.splitext(output); safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("._") or "target"; path = f"{stem}_{safe}{ext}"
            save_report(path, scanner, report)
    return 0


def build_cli_parser() -> argparse.ArgumentParser:
    return build_parser()


def local_selftest(port: int = 8080) -> None:
    table = Table(title="M-Recon Self-Test", header_style="bold cyan")
    table.add_column("K"); table.add_column("ST"); table.add_column("D")
    checks = []
    checks.append(("PY", True, platform.python_version()))
    checks.append(("RI", True, "Rich"))
    checks.append(("SC", SCAPY_AVAILABLE, "Scapy"))
    checks.append(("CR", CRYPTO_AVAILABLE, "cryptography"))
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
ACTIVE_THREAD: Optional[threading.Thread] = None
ACTIVE_SCANNER: Optional[MReconScanner] = None
ACTIVE_ERROR: Optional[str] = None
SESSION_CONFIG = ScanConfig()
SESSION_EXPLICIT_FIELDS: set[str] = set()

BANNER = r"""[bold cyan]
███╗   ███╗███╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗
████╗ ████║████╗  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║██╔██╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╔╝██║██║╚██╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║ ╚████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]"""

HELP_TEXT = f"""
[bold cyan]M-Recon v{V15_VERSION}[/bold cyan]

[bold]Start[/bold]
  ms

[bold]Scan[/bold]
  scan <target> [ports]
  scan <target> [ports] -U   add UDP probes
  scan <target> [ports] -S   SYN mode
  scan <target> [ports] -F   SYN fragment mode
  scan <target> [ports] -d   deep
  scan <target> [ports] -q   fast

[bold]Options[/bold]
  -w N    workers
  -t N    timeout
  -r N    rate/sec
  -fw N   fingerprint workers
  -b N    banner timeout
  -m N    HTTP bytes
  -o F    JSON/CSV/HTML report
  -cf F   config
  -pl D   plugins

[bold]Shell[/bold]
  -h        help
  -V        version
  -st       status
  -c        clear
  cfg       auto/manual policy
  cfg set K V  set a runtime default
  detail N  full details for port N
  tst [N]   self-test
  pause     pause between scan batches
  resume    resume
  stop      stop current scan
  -x        exit

[bold]Examples[/bold]
  scan 127.0.0.1
  scan 127.0.0.1 80,443
  scan 127.0.0.1 web
  scan 127.0.0.1 1-1024 -U
  scan 127.0.0.1 1-1024 -U -d -w 64 -r 100
"""


def _clone_config(cfg: ScanConfig) -> ScanConfig:
    return ScanConfig(**{k: getattr(cfg, k) for k in ScanConfig.__dataclass_fields__ if k != "lock"})

def _apply_cfg_override(cfg: ScanConfig, key: str, value: str) -> None:
    mapping = {
        "w": ("workers", int),
        "t": ("timeout", float),
        "r": ("max_requests_per_second", float),
        "fw": ("fingerprint_workers", int),
        "b": ("banner_timeout", float),
        "m": ("max_http_bytes", int),
        "pl": ("plugins_dir", str),
        "o": ("output", str),
    }
    if key not in mapping:
        raise ValueError("Unknown cfg key")
    attr, cast = mapping[key]
    setattr(cfg, attr, cast(value))

def _run_async_scan(args) -> None:
    global LAST_REPORT, LAST_SCANNER, ACTIVE_SCANNER, ACTIVE_ERROR, ACTIVE_THREAD
    try:
        _normalize_cli_target(args)
        cfg = _clone_config(SESSION_CONFIG)
        # map explicit CLI args onto session config via run_scan compatibility
        if args.workers is not None: cfg.workers = args.workers
        if args.timeout is not None: cfg.timeout = args.timeout
        if args.rate is not None: cfg.max_requests_per_second = args.rate
        if args.fingerprint_workers is not None: cfg.fingerprint_workers = args.fingerprint_workers
        if args.banner_timeout is not None: cfg.banner_timeout = args.banner_timeout
        if args.max_http_bytes is not None: cfg.max_http_bytes = args.max_http_bytes
        if args.syn: cfg.syn_mode = True
        if args.fragment: cfg.fragment = True
        if args.udp: cfg.udp = True
        if args.profile: cfg.profile = args.profile
        ports = _parse_port_value(args.ports)
        targets = expand_target_spec(args.target, cfg.max_hosts)
        jobs = len(targets) * len(ports) + (len(targets) * sum(1 for p in ports if p in UDP_PROBES) if cfg.udp else 0)
        explicit = set(SESSION_EXPLICIT_FIELDS)
        if args.workers is not None: explicit.add("workers")
        if args.timeout is not None: explicit.add("timeout")
        if args.rate is not None: explicit.add("max_requests_per_second")
        if args.fingerprint_workers is not None: explicit.add("fingerprint_workers")
        if args.banner_timeout is not None: explicit.add("banner_timeout")
        if args.max_http_bytes is not None: explicit.add("max_http_bytes")
        if args.profile is not None: explicit.add("profile")
        _auto_tune(cfg, jobs, cfg.profile, explicit)
        cfg.auto_mode = not bool(explicit)
        registry = build_default_registry(); load_plugins(registry, cfg.plugins_dir)
        for target in targets:
            scanner = MReconScanner(target, cfg, registry)
            ACTIVE_SCANNER = scanner
            report = scanner.run(ports, None)
            LAST_SCANNER = scanner; LAST_REPORT = report
        console.print("[bold green][+] Scan complete.[/bold green]")
    except Exception as exc:
        ACTIVE_ERROR = str(exc)
        console.print(f"[bold red][!] Scan error: {escape(str(exc))}[/bold red]")
    finally:
        ACTIVE_SCANNER = None; ACTIVE_THREAD = None

def start_background_scan(args) -> None:
    global ACTIVE_THREAD
    if ACTIVE_THREAD and ACTIVE_THREAD.is_alive():
        console.print("[yellow]A scan is already running. Use status/pause/stop.[/yellow]")
        return
    ACTIVE_THREAD = threading.Thread(target=_run_async_scan, args=(args,), daemon=True)
    ACTIVE_THREAD.start()
    console.print("[cyan][*] Scan started in background.[/cyan]")


def _shell_args(parts: list[str]) -> argparse.Namespace:
    if not parts or parts[0].lower() != "scan":
        raise SystemExit("Use: scan <target> [ports] [options]")
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
    rest = parts[idx:]
    mapping = {"-w": ("workers", int), "-t": ("timeout", float), "-r": ("rate", float), "-fw": ("fingerprint_workers", int), "-b": ("banner_timeout", float), "-m": ("max_http_bytes", int), "-o": ("output", str), "-cf": ("config", str), "-pl": ("plugins_dir", str)}
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "-T":
            i += 1; continue
        if tok == "-U":
            args.udp = True; i += 1; continue
        if tok == "-S":
            args.syn = True; i += 1; continue
        if tok == "-F":
            args.fragment = True; i += 1; continue
        if tok == "-d":
            args.profile = "deep"; i += 1; continue
        if tok == "-q":
            args.profile = "fast"; i += 1; continue
        if tok not in mapping:
            raise SystemExit(f"Unknown option: {tok}")
        if i + 1 >= len(rest):
            raise SystemExit(f"{tok} needs a value")
        attr, cast = mapping[tok]
        setattr(args, attr, cast(rest[i + 1]))
        i += 2
    return args


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
        if low in {"-h", "help"}:
            console.print(HELP_TEXT); continue
        if command == "-V" or low == "version":
            console.print(f"[bold cyan]M-Recon v{V15_VERSION}[/bold cyan]"); continue
        if low in {"-st", "status"}:
            print_status(); continue
        if low in {"-c", "clear"}:
            console.clear(); print_banner(); continue
        if low in {"-rt", "reports"}:
            if LAST_REPORT and LAST_SCANNER:
                console.print(f"[cyan]Last report: {LAST_REPORT.get('target', 'N/A')} | results={len(LAST_REPORT.get('results', []))}[/cyan]")
            else:
                console.print("[cyan]No report in this session.[/cyan]")
            continue
        if low in {"cfg", "config"}:
            if len(tokens) >= 4 and tokens[1].lower() == "set":
                try:
                    _apply_cfg_override(SESSION_CONFIG, tokens[2].lstrip("-"), tokens[3])
                    console.print(f"[green]cfg {tokens[2]}={tokens[3]}[/green]")
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
        if low == "pause":
            if ACTIVE_SCANNER:
                ACTIVE_SCANNER.pause_event.clear(); console.print("[yellow]Paused after current batch.[/yellow]")
            else: console.print("[yellow]No active scan.[/yellow]")
            continue
        if low == "resume":
            if ACTIVE_SCANNER:
                ACTIVE_SCANNER.pause_event.set(); console.print("[green]Resumed.[/green]")
            else: console.print("[yellow]No active scan.[/yellow]")
            continue
        if low == "stop":
            if ACTIVE_SCANNER:
                ACTIVE_SCANNER.stop_event.set(); ACTIVE_SCANNER.pause_event.set(); console.print("[red]Stop requested.[/red]")
            else: console.print("[yellow]No active scan.[/yellow]")
            continue
        if low in {"-pl", "plugins"}:
            console.print("[cyan]Use -pl <dir> during scan to load probes.[/cyan]"); continue
        if low != "scan":
            console.print("[bold red][!] Unknown command. Use -h.[/bold red]"); continue
        try:
            args = _shell_args(tokens)
            start_background_scan(args)
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
    if raw and raw[0] == "ms":
        rest = raw[1:]
        if not rest:
            return interactive_shell()
        if rest[0] in {"-V", "--version"}:
            console.print(f"M-Recon {V15_VERSION}")
            return 0
        if rest[0] == "-h":
            console.print(HELP_TEXT)
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
