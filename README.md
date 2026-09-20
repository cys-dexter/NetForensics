# NetForensics: Enterprise Network Forensics & PCAP Artifact Collector

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Author](https://img.shields.io/badge/Developer-Ahmad-brightgreen?style=flat-square)](https://github.com/cys-dexter)
[![GitHub](https://img.shields.io/badge/GitHub-cys--dexter-blue?style=flat-square&logo=github)](https://github.com/cys-dexter)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20POSIX-orange?style=flat-square&logo=linux)](https://kernel.org)
[![DFIR Category](https://img.shields.io/badge/DFIR-Network%20Forensics-red?style=flat-square)](https://github.com/cys-dexter)

**NetForensics** is a high-performance, enterprise-grade Digital Forensics and Incident Response (DFIR) artifact extraction and threat inspection suite developed in Go (Golang). Built for Security Operations Center (SOC) analysts, incident responders, and forensic investigators, NetForensics enables passive real-time packet capture, deep offline `.pcap` / `.pcapng` parsing, bidirectional TCP stream reassembly, automated file carving, cryptographic integrity hashing (SHA-256 / MD5), multi-vector threat detection, and forensic timeline generation exportable to RFC 4180 CSV and structured JSON.

---

## 👨‍💻 Author & Attribution

- **Lead Systems & DFIR Engineer:** Ahmad
- **GitHub Profile:** [@cys-dexter](https://github.com/cys-dexter)
- **Repository:** [https://github.com/cys-dexter/netforensics](https://github.com/cys-dexter)

---

## 🚀 Core Forensic Capabilities

### 1. Passive Packet Capture & PCAP Parsing
- **Dual Ingestion Engine:** Supports live packet capture via `libpcap` / `afpacket` across network interfaces with hardware timestamps and promiscuous mode.
- **Offline Forensics:** Resilient offline inspection supporting legacy `.pcap` and modern `.pcapng` files with automatic header detection and pure-Go fallback.
- **Hardware-Accelerated Filtering:** In-kernel Berkeley Packet Filter (BPF) offloading to capture only relevant forensic flows (e.g. `tcp port 80 or udp port 53`).

### 2. TCP Stream Reassembly & Automated File Carving
- **Stateful Stream Assembly:** Bidirectional TCP connection tracking (4-tuple sequencing, overlapping segments, out-of-order packet reordering).
- **HTTP Payload Carving:** Unpacks HTTP requests and responses, decodes `Transfer-Encoding: chunked`, resolves `Content-Disposition: attachment; filename="..."`, and extracts transferred payloads directly into `./extracted_artifacts/`.
- **FTP Data Extraction:** Monitors FTP control channels (port 21) for `RETR`, `STOR`, `PASV`, and `PORT` commands, correlating incoming dynamic data streams with original file transfers.
- **Magic-Byte Sniffing:** Identifies Windows PE Executables (`.exe`, `.dll`), Linux Binaries (`.elf`), Documents (`.pdf`, `.docx`), Archives (`.zip`, `.7z`, `.gz`), Images (`.png`, `.jpg`), and Scripts (`.sh`).

### 3. Automated Cryptographic Hashing
- **Dual-Stream Hashing:** Simultaneously calculates cryptographic **SHA-256** and **MD5** hashes for every extracted artifact and payload in real-time.
- **Chain of Custody:** Establishes forensic integrity verification with non-repudiation ledgers and timeline evidence hashes.

### 4. Real-Time Threat Detection & Anomaly Inspection
- **DNS Tunneling & Data Exfiltration:**
  - Dynamic Shannon Entropy calculation ($-\sum P(x) \log_2 P(x)$) over subdomains.
  - Flags queries exceeding baseline length ($> 45$ characters) or displaying Base32, Hex, or Base64 C2 encoding patterns (e.g., Cobalt Strike, iodine, dnscat2).
- **ARP Poisoning & MITM Detection:**
  - Maintains stateful in-memory IP-to-MAC hardware bindings.
  - Detects MAC flip-flop / cache poisoning attacks attempting to hijack default gateways.
  - Flags unsolicited Gratuitous ARP broadcasts.
- **Stealth Port Scanning Fingerprinting:**
  - Flags RFC 793 evasion scans: **Xmas Tree Scan** (`FIN+PSH+URG`), **Null Scan** (no flags set), and **FIN Scan** (`FIN` without `ACK`).
  - Identifies **Robert Graham Masscan** fingerprint via static TCP window sizing (`Window: 1024`).
  - Detects rapid horizontal and vertical TCP port sweeps across configurable sliding time windows.

### 5. Evidence Timeline & Exporting
- **Chronological Audit Trail:** Aggregates packet events, threat alerts, and carved artifacts into an immutable timeline.
- **Structured Exporters:** One-click export to formatted **JSON** or RFC 4180 **CSV** for ingestion into Splunk, Elastic SIEM, or forensic case files.

---

## 🖥️ Dual-Mode User Interface

### Mode 1: Interactive TUI Dashboard (Terminal UI)
Built with `rivo/tview` and `gdamore/tcell/v2`, NetForensics provides a visual terminal console with real-time updates and keyboard navigation:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ NetForensics v1.0.0 | DFIR Network Forensics & PCAP Artifact Collector | Ahmad         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Packets: 12,450 | Volume: 8.42 MB | Rate: 1,420 pkt/s | Carved: 7 | 🔴 Threat Detected │
├──────────────────────────────────────────┬─────────────────────────────────────────────┤
│ [1] Live Packets Stream (Focus: '1')     │ [2] Forensic Threat Alerts (Focus: '2')     │
│ 13:00:00.100  192.168.1.100 -> 8.8.8.8   │ 🔴 THREAT | DNS Tunneling / Exfiltration    │
│ 13:00:00.600  192.168.1.1   -> 192.168.1 │ 🔴 THREAT | ARP Cache Poisoning / MITM      │
│ 13:00:01.000  10.0.0.99     -> 192.168.1 │ 🔴 THREAT | TCP Xmas Tree Scan (Nmap -sX)   │
├──────────────────────────────────────────┼─────────────────────────────────────────────┤
│ [3] Carved Artifacts & Hashes ('3'/'f')  │ [4] Evidence Timeline (Focus: '4')          │
│ 🔴 beacon.exe (68 B) [SHA256: f820e5...] │ 13:00:00.100 [THREAT] DNS Covert Channel    │
│ 🟢 manual.pdf (2.4 MB)[SHA256: a1b2c3...]│ 13:00:00.600 [THREAT] ARP Gateway Claimed   │
├──────────────────────────────────────────┴─────────────────────────────────────────────┤
│ [Tab] Cycle Panes | [1-4] Select | [e] Export Timeline | [f] Artifacts | [q] Quit      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

#### TUI Keyboard Shortcuts:
| Key | Action |
|:---|:---|
| `Tab` / `Shift+Tab` | Cycle focus across tables |
| `1` | Focus Live Packets Table |
| `2` | Focus Forensic Threat Alerts Panel |
| `3` or `f` | Focus Carved Artifacts Table / Open Inspector |
| `4` | Focus Evidence Timeline Table |
| `Arrow Keys` | Scroll up/down through records in active pane |
| `e` | Open interactive Timeline Export dialog (JSON / CSV) |
| `?` or `F1` | Show modal Help dialog and Keybindings Cheatsheet |
| `q` or `Ctrl+C` | Gracefully quit and finalize evidence logs |

---

### Mode 2: Non-Interactive CLI Mode (Headless)
Run NetForensics in automated scripts, Docker containers, or SOC ingestion pipelines using `-headless`:

```bash
./bin/netforensics -r capture.pcapng -headless -timeline evidence.json -o json -out-dir ./extracted_artifacts
```

---

## 📁 Project Architecture & Layout

Following standard Go project standards:

```
NetForensics/
├── cmd/
│   └── netforensics/
│       └── main.go                  # CLI flag parsing, banner, signal handling, mode routing
├── pkg/
│   ├── capture/
│   │   ├── capture.go               # Live capture & offline reader engine, BPF filtering
│   │   └── stats.go                 # Atomic performance metrics & packet statistics
│   ├── reassembly/
│   │   ├── stream.go                # TCP stream reassembly & connection tracker
│   │   ├── carver.go                # MIME sniffing, signature detection, artifact hashing
│   │   └── ftp.go                   # FTP control parsing & data transfer correlation
│   ├── forensics/
│   │   ├── engine.go                # Threat detection orchestrator & subscription broker
│   │   ├── models.go                # Alert models, threat levels (🟢, 🟡, 🔴)
│   │   ├── hasher.go                # Dual-stream MD5 & SHA-256 cryptographic hashing
│   │   ├── dns_tunnel.go            # Shannon entropy calculation & DNS covert channel detection
│   │   ├── arp_poison.go            # Dynamic ARP inspection & MITM detection
│   │   ├── port_scan.go             # SYN, FIN, NULL, XMAS, Masscan fingerprinting
│   │   └── forensics_test.go        # Unit tests for threat detection algorithms
│   ├── protocols/
│   │   ├── parser.go                # Layer 2-7 packet dissector & TLS SNI extractor
│   │   ├── types.go                 # Protocol models & severity levels
│   │   ├── dns.go                   # DNS parser & subdomain extraction
│   │   ├── arp.go                   # ARP parser & gratuitous broadcast detector
│   │   ├── http.go                  # HTTP request/response dissector & filename extraction
│   │   └── protocols_test.go        # Protocol decoder unit tests
│   ├── reporter/
│   │   ├── timeline.go              # Forensic timeline model, event sequencing & integrity hash
│   │   ├── export_json.go           # Structured DFIR JSON exporter
│   │   ├── export_csv.go            # RFC 4180 CSV exporter
│   │   └── reporter_test.go         # Timeline and export unit tests
│   └── ui/
│       ├── tui.go                   # Main TUI controller & metrics refresher
│       ├── views.go                 # Split table views (Packets, Alerts, Artifacts, Timeline)
│       └── keybindings.go           # Key event captures & modal dialogs
├── testdata/
│   ├── generate_pcaps.go            # Synthetic forensic PCAP generator
│   └── forensic_sample.pcap         # Sample PCAP containing real-world attack scenarios
├── bin/
│   └── netforensics                 # Compiled production binary
├── extracted_artifacts/             # Destination for carved files and payloads
├── go.mod                           # Go module definition
├── go.sum                           # Dependency checksums
└── README.md                        # Project documentation
```

---

## 🛠️ Step-by-Step Installation & Build

### Prerequisites
- **Operating System:** Linux (Ubuntu/Debian, Fedora, Arch, CentOS) or macOS.
- **Go Compiler:** Go `1.22` or later.
- **Libraries:** `libpcap` development headers.

#### Install Dependencies:
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y libpcap-dev build-essential

# Fedora / RHEL
sudo dnf install -y libpcap-devel gcc

# Arch Linux
sudo pacman -S libpcap
```

### Build from Source:
```bash
# 1. Clone repository
git clone https://github.com/cys-dexter/netforensics.git
cd netforensics

# 2. Verify dependencies
go mod verify

# 3. Build optimized binary
mkdir -p bin
go build -ldflags="-s -w" -o bin/netforensics ./cmd/netforensics
```

### Run Unit Tests:
```bash
go test -v -race ./...
```

---

## 📖 Usage Examples

### 1. Interactive TUI Analysis of an Offline PCAP:
```bash
./bin/netforensics -r suspicious_traffic.pcap
```

### 2. Live Network Sniffing on `eth0` with BPF Filter:
```bash
sudo ./bin/netforensics -i eth0 -bpf "port 80 or port 53 or port 21"
```

### 3. Automated Headless Forensics with JSON Timeline Export:
```bash
./bin/netforensics -r malware_c2.pcapng \
  -headless \
  -out-dir ./investigation_artifacts \
  -timeline evidence_report.json \
  -o json
```

### 4. Exporting Timeline to CSV for SIEM (Splunk / Elastic):
```bash
./bin/netforensics -r compromise.pcap \
  -headless \
  -timeline evidence_report.csv \
  -o csv
```

---

## 🛡️ Sample Investigation Output

```
================================================================================
                    NETFORENSICS DFIR INVESTIGATION SUMMARY                    
================================================================================
  Lead Investigator:    Ahmad
  GitHub Reference:     https://github.com/cys-dexter
  Session Duration:     1.42s
  Packets Ingested:     23 (16 pkt/s)
  Traffic Volume:       1,714 bytes
  Carved Artifacts:     1 files (Saved to: ./extracted_artifacts)
  Forensic Alerts:      20 detected
  Timeline Events:      22 chronological records
  Evidence Hash (SHA):  edeca5e53cf27865a40dc4dfac25762c177f0b7f7e4e8fdc46c35367b0efd7fb
================================================================================
```

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for details.
