# M-Recon v15.16

**M-Recon** is a protocol-aware reconnaissance scanner designed for authorized security testing and network visibility.

It supports **IPv4 and IPv6 TCP scanning**, optional **SYN scanning with Scapy/Npcap**, **UDP protocol probes**, adaptive timeouts, bounded concurrency, rate limiting, service/version fingerprinting, **HTTP and TLS inspection**, WAF/CDN hints, reverse DNS, transparent exposure/risk scoring, Web Recon, plugins, configuration files, and structured reporting.

### Key Features

* IPv4 + IPv6 scanning
* TCP Connect and optional SYN scanning
* UDP probes for supported services
* Adaptive timeouts and rate limiting
* Concurrent scanning with bounded workers
* Protocol-aware service fingerprinting
* SSH, HTTP/HTTPS, FTP, SMTP, POP3, IMAP, MySQL, Redis, Memcached, PostgreSQL, MongoDB, AMQP/RabbitMQ, VNC, and RDP probes
* TLS inspection with:

  * TLS version
  * Cipher
  * Certificate Subject
  * Certificate Issuer
  * SAN
  * Validity dates
  * Remaining certificate lifetime
  * SHA-256 certificate fingerprint
  * Optional trust verification
* IPv4/IPv6-aware SNI handling
* HTTP headers, titles, redirects, technologies, robots.txt, sitemap.xml, and security.txt reconnaissance
* WAF/CDN provider hints with confidence levels
* Evidence-weighted exposure/risk scoring
* JSON, CSV, and interactive HTML reports
* TOML/JSON configuration
* External probe plugins
* Interactive terminal shell
* Cache support
* Self-test and runtime status checks
* Unit/integration-friendly architecture

### Important

M-Recon is intended **only for systems and networks you are authorized to assess**. It reports observable service/exposure evidence and does not claim to identify vulnerabilities by default.
