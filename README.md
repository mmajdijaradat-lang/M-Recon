# M-Recon

Advanced terminal-first reconnaissance scanner for authorized security testing.

## Highlights

- Rich terminal UI with M-Recon banner and interactive shell
- TCP Connect scanning
- Optional IPv4 SYN probes with Scapy and elevated privileges
- IPv4 and IPv6 target resolution
- Optional UDP probes with explicit response states
- Adaptive timeouts, bounded concurrency, and rate limiting
- Protocol-aware HTTP/TLS and service fingerprinting
- Reverse DNS
- WAF/CDN provider hints with confidence and evidence
- Evidence-based exposure/risk scoring (not vulnerability claims)
- JSON, CSV, and HTML reporting
- TOML/JSON configuration
- External probe plugins
- Fast / balanced / deep profiles

## Requirements

Python 3.10+ is recommended.

```powershell
py -m pip install -r requirements.txt
```

## Start the terminal UI

```powershell
py MRecon.py
```

This opens the Rich interactive shell:

```text
mrecon>
```

## Example

Use a target you are authorized to assess:

```text
scan -t 127.0.0.1 -p 1-1024
```

Or from PowerShell:

```powershell
py MRecon.py -t 127.0.0.1 -p 1-1024
```

## Safety

Use M-Recon only on systems and networks you own or are explicitly authorized to test.
The scanner reports exposure and protocol evidence; it does not by itself prove a vulnerability.
