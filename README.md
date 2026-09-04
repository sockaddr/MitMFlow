# MitMFlow

**Passive ARP man-in-the-middle suite for reconstructing a victim's browsing destinations — from encrypted traffic, without degrading their connection.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![scapy](https://img.shields.io/badge/pip-scapy-green.svg)](https://scapy.readthedocs.io/)
[![Platform-Linux/Kali](https://img.shields.io/badge/Platform-Linux%2F%20Kali-black.svg)]()

> ⚠️ **For licensed security professionals only.** Use exclusively on networks you own or are explicitly authorized to test.

---

## Overview

MitMFlow performs a **bidirectional ARP poisoning** session against a target on your local segment and passively parses the *metadata* that stays readable even when traffic is TLS-encrypted. Unlike active DNS spoofing or inline proxy rewriting, it **never alters or blocks** the victim's traffic — you simply read what's already in transit.

Every observed destination is committed to a user-defined `.pcap` and aggregated into a **noise-filtered activity report**, so CDN/telemetry chatter doesn't bury the real targets.

---

## ✨ Features

- 🦀 **HTTPS-proof host enumeration** — extracts `SNI` (`server_name`) straight from TLS `ClientHello` records (RFC 6066 parser, TLS 1.2 & 1.3).
- 🌐 **Plaintext DNS capture** — logs query names from port 53 before encryption kicks in.
- 🐌 **Legacy HTTP `Host` read** — catches old-style cleartext navigation on port 80.
- 📦 **Auto noise filtering** — suppresses Google/Cloudflare/Apple/CDN/analytics/captive-portal chatter.
- 🔁 **Bidirectional stealth** — poisons both victim ↔ gateway so *all* cross-traffic is visible.
- 🧹 **Self-restoring** — ARP tables and forwarding state are reverted cleanly on exit.
- 📟 **Live console telemetry** — real-time metadata feed while the session runs.
- 💾 **`.pcap` export** — full frame capture for later analysis.
- 🔭 **Segment scanner** — `--scan-only` host discovery mode included.

---

## How it recovers destinations

| Signal | Sampled from | What it reveals |
|--------|-------------|-----------------|
| **SNI** | TLS `ClientHello` (p. 443) | Exact destination host, works over `https://` | | 
| **DNS** | Plaintext queries (u. 53) | Requested domain / resolution |
| **HTTP `Host`** | Request headers (p. 80) | Cleartext navigation |

---

## Attack flow

```
 1. ARP sweep the /24 segment        → list live hosts + gateway
 2. Pick the victim                  → --target / interactive index
 3. Bidirectional ARP poison         → victim ↔ gateway routed via us
 4. Enable IP forward (/proc/sys)    → transparent, non-disruptive
 5. Sniff & parse (SNI/DNS/HTTP)     → passive, metadata only
 6. Ctrl+C                           → ARP restored, forwarding reverted
 7. Report + optional .pcap          → ranked destination tree
```

The poisoner and the sniffer run as independent threads; the tool only ever *reads* metadata in transit.

---

## Requirements

- **OS**: Linux (developed on Kali)
- **Privileges**: root (raw sockets + forwarding)
- **Python 3.8+** with dependencies:

```bash
pip3 install scapy
```

---

## Usage

```bash
sudo python3 main.py [--target 192.168.1.34]
sudo python3 main.py --iface wlo1 --gateway 192.168.1.1
sudo python3 main.py --scan-only
```

### Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--iface` | auto | Interface to operate on |
| `--target` | prompt | Victim IP |
| `--gateway` | auto | Gateway IP (routing table) |
| `--scan-only` | — | Discover hosts, then exit |
| `--pcap PATH` | prompt | Output capture path |
| `--no-sni` | — | Disable TLS SNI parsing |

### Interactive session

```bash
sudo python3 main.py
[+] Engagement — victim 192.168.1.34 (aa:bb:cc:dd:ee:ff) ↔ gw 192.168.1.1
[~] Forwarding ON. Capturing SNI/DNS/HTTP until Ctrl+C.

# live feed:
[*] [192.168.1.34] TLS/SNI github.com:443 | frags=142

# final report:
█ PRIMARY — hosts the victim contacted (SNI/DNS/HTTP)
  ● github.com       [SNI] 
  ● api.notion.so    [TLS]
  ● docs.python.org  [DNS]
```

### Sample output

```
======================================================================
   DESTINATION RECONSTRUCTION — victim 192.168.1.34
======================================================================

█ PRIMARY — host the victim contacted (SNI/DNS/HTTP)
------------------------------------------------------------------------
  ● github.com                       [SNI]   tot 3
  ● api.notion.so                    [TLS]   tot 5
  ● docs.python.org                  [DNS]   tot 2

█ ASSET/SUPPORT noise (CDN/API echo): 14 suppressed
Capture → m_192.168.1.34_1690000000.pcap
```

---

## 🗂️ Project layout

```
.
├── main.py          # Single-file entrypoint (CLI, ARP, parser, report)
└── README.md
```

> The tool is deliberately **self-contained in one file** (`main.py`) for easy deployment and transfer.

---

## 🧰 Extensibility

- **Noise filter** — regex list in `NOISE` at module top; edit to fit your target environment.
- **Parser** — `parse_sni()` is isolated and callable on arbitrary bytes for unit tests or reuse.
- **Report scoping** — weighting heuristic (`st()` scoring) is tunable for your engagement style.

---

## ⚖️ Ethical use & authorization

This is an **offensive security research tool**. By using it, you confirm that:

1. You are testing a network you **own** or have **explicit written authorization** to assess.
2. You will not target infrastructure belonging to third parties without permission.
3. Unauthorized network interception may be illegal in your jurisdiction — you are responsible for compliance (e.g., CFAA, EU GDPR §81, national computer-misuse legislation).

**Recommended environment:** isolated lab/VLAN, CTF ranges, or credentialed engagements.
