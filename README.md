# NetForensics

### Enterprise Network Forensics & PCAP Artifact Collector | DFIR Investigation Suite

**Developer:** Ahmad  
**GitHub:** https://github.com/cys-dexter  
**Version:** `1.0.0`

[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![DFIR](https://img.shields.io/badge/DFIR-Network%20Forensics-red?style=flat-square)]
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20POSIX-orange?style=flat-square)]
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

---

## 📖 Overview

**NetForensics** is an enterprise-oriented **Network Forensics and Digital Forensics & Incident Response (DFIR)** investigation suite written in **Go (Golang)**.

It is designed for security analysts, SOC teams, incident responders, and forensic investigators who need to inspect network traffic, analyze PCAP evidence, identify suspicious network behavior, extract transferred artifacts, calculate forensic hashes, and produce structured investigation reports.

NetForensics supports two primary investigation workflows:

1. **Offline Forensics** — analyze previously captured `.pcap` and `.pcapng` files.
2. **Live Network Monitoring** — capture packets directly from a selected network interface.

The project includes packet parsing, TCP stream reassembly, artifact carving, cryptographic hashing, threat detection, forensic timeline generation, and JSON/CSV export capabilities.

---

# 🚀 Key Features

## Offline Forensics

Analyze existing PCAP and PCAPNG captures without performing live packet capture.

```bash
./bin/netforensics -r capture.pcap
```

Supported forensic workflows include packet inspection, protocol analysis, stream reconstruction, threat detection, artifact extraction, and timeline generation.

---

## Live Network Traffic Monitoring

Capture packets directly from a network interface using `libpcap`.

```bash
sudo ./bin/netforensics -i eth0
```

Live capture may require elevated privileges depending on the operating system and network-interface permissions.

---

## Threat Detection Engine

NetForensics includes multiple network-threat detection mechanisms, including:

- **ARP Poisoning / ARP Cache Poisoning**
- **Man-in-the-Middle (MITM) indicators**
- **TCP Port Scanning**
- **Xmas Tree scans**
- **NULL scans**
- **FIN scans**
- **Rapid port sweeps**
- **DNS tunneling / suspicious DNS activity**
- **Possible DNS-based data exfiltration**
- **Masscan-style TCP fingerprinting**

The existing project implementation documents stateful ARP inspection, DNS entropy analysis, and several TCP scanning fingerprints.

---

## Artifact Carving & Forensic Extraction

NetForensics can reconstruct relevant network streams and extract transferred payloads.

The forensic pipeline includes:

- TCP stream reassembly
- HTTP payload extraction
- FTP transfer correlation
- File-signature / magic-byte detection
- Artifact extraction
- SHA-256 hashing
- MD5 hashing
- Evidence timeline integration

Extracted artifacts are written to:

```text
./extracted_artifacts/
```

The documented artifact pipeline includes HTTP and FTP extraction as well as magic-byte identification for executables, documents, archives, images, and scripts.

---

## 📊 JSON & CSV Reporting

Investigation data can be exported in structured formats suitable for further analysis.

Supported formats include:

- **JSON**
- **CSV**

The project documentation specifically describes JSON and RFC 4180 CSV timeline exporters for forensic and SIEM workflows.

---

## 🖥️ Interactive TUI

NetForensics includes an interactive Terminal User Interface for monitoring:

- Live packets
- Threat alerts
- Carved artifacts
- Evidence timeline

The documented interface provides dedicated views for packet activity, forensic alerts, artifacts, and timeline events.

### TUI Keyboard Shortcuts

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Cycle between interface panels |
| `1` | Focus Live Packets |
| `2` | Focus Threat Alerts |
| `3` / `f` | Focus Carved Artifacts |
| `4` | Focus Evidence Timeline |
| `Arrow Keys` | Navigate records |
| `e` | Open timeline export |
| `?` / `F1` | Open help |
| `q` / `Ctrl+C` | Quit gracefully |

These shortcuts are documented by the project's existing TUI specification.

---

# 📋 Prerequisites

Before installing NetForensics, make sure the following requirements are available.

## Go 1.22+

NetForensics requires:

```text
Go 1.22 or newer
```

Check your installed version:

```bash
go version
```

Example:

```text
go version go1.22.x linux/amd64
```

If your installed version is older than `1.22`, upgrade Go before building the project.

---

## libpcap

Live packet capture requires the `libpcap` development libraries.

### Ubuntu / Debian

Install all required system packages with:

```bash
sudo apt update && sudo apt install -y libpcap-dev git build-essential
```

The project documentation identifies `libpcap` development headers as a required dependency.

---

# 🛠️ Installation & Build

## ⚠️ Important Permission Rule

**Do not run `go build` with `sudo`.**

Avoid:

```bash
sudo go build ...
```

Running the Go build as `root` can create root-owned files and directories inside the project, particularly under:

```text
bin/
```

This can later cause:

```text
Permission denied
```

when your normal user attempts to overwrite or remove the generated executable.

### Correct approach

Use `sudo` only when administrative privileges are actually required, such as:

- Installing system packages.
- Capturing packets from a restricted network interface.
- Repairing ownership of files that were previously created by `root`.

Run the Go build itself as your normal user.

---

## 1. Clone the Repository

```bash
git clone https://github.com/cys-dexter/NetForensics.git
```

Enter the project directory:

```bash
cd NetForensics
```

---

## 2. Verify Dependencies

Run:

```bash
go mod verify
```

This verifies the downloaded Go modules against their expected checksums.

---

## 3. Prepare the Build Directory

Create a clean `bin` directory:

```bash
rm -rf bin && mkdir -p bin
```

Do **not** use `sudo` here.

---

## 4. Build NetForensics

Build the optimized executable:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

Again, **do not add `sudo`**.

After a successful build, the executable will be:

```text
bin/netforensics
```

Verify it:

```bash
ls -lh bin/netforensics
```

---

# 🔧 Permission Troubleshooting

If you previously built the project using `sudo`, your project may contain files owned by `root`.

Check ownership:

```bash
ls -ld .
ls -ld bin
```

If `bin` or project files are owned by `root`, repair the ownership:

```bash
sudo chown -R "$USER:$USER" .
```

Then recreate the build directory:

```bash
rm -rf bin && mkdir -p bin
```

Finally rebuild normally:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

### Do not solve the problem by repeatedly using `sudo go build`

The preferred solution is:

```text
Fix ownership → clean bin/ → build as normal user
```

---

# ▶️ Usage

After building the project successfully, verify the command-line interface:

```bash
./bin/netforensics --help
```

This should be the first command used to inspect the available options supported by the compiled application.

---

## Offline PCAP Analysis

Analyze an existing capture:

```bash
./bin/netforensics -r /path/to/capture.pcap
```

Example:

```bash
./bin/netforensics -r suspicious_traffic.pcap
```

PCAPNG example:

```bash
./bin/netforensics -r suspicious_traffic.pcapng
```

The documented offline mode uses `-r` to provide the PCAP input file.

---

# 🌐 Live Network Capture

To capture packets from a network interface:

```bash
sudo ./bin/netforensics -i eth0
```

Replace `eth0` with the interface available on your system.

List interfaces on Linux:

```bash
ip link
```

Possible interfaces include:

```text
eth0
ens33
enp0s3
wlan0
```

Example:

```bash
sudo ./bin/netforensics -i wlan0
```

Live capture is the scenario where elevated privileges may be required. The project's documented usage also invokes the binary with `sudo` for live sniffing.

---

# 🎯 BPF Filtering

NetForensics supports Berkeley Packet Filter expressions for narrowing live capture traffic.

Example:

```bash
sudo ./bin/netforensics -i eth0 -bpf "port 80 or port 53 or port 21"
```

This limits captured traffic to the specified ports.

Another example:

```bash
sudo ./bin/netforensics -i eth0 -bpf "tcp port 80 or udp port 53"
```

BPF filtering is designed to reduce unnecessary traffic and focus the investigation on relevant flows.

---

# 🤖 Headless / Automated Mode

NetForensics provides a non-interactive mode using:

```text
-headless
```

This is useful for automation, scripts, containers, and SOC ingestion pipelines.

Example:

```bash
./bin/netforensics \
  -r capture.pcapng \
  -headless \
  -timeline evidence.json \
  -o json \
  -out-dir ./extracted_artifacts
```

The documented headless workflow combines PCAP input with timeline output, an output format, and an artifact directory.

---

# 📄 Timeline Export

## JSON

Generate a JSON forensic timeline:

```bash
./bin/netforensics \
  -r capture.pcapng \
  -headless \
  -timeline evidence.json \
  -o json \
  -out-dir ./extracted_artifacts
```

---

## CSV

Export the timeline as CSV:

```bash
./bin/netforensics \
  -r compromise.pcap \
  -headless \
  -timeline evidence_report.csv \
  -o csv
```

The project documentation describes the CSV exporter as RFC 4180 compatible and intended for structured forensic/SIEM workflows.

---

# 🧪 Running Tests

Run the complete test suite:

```bash
go test -v -race ./...
```

### Options

| Option | Purpose |
|---|---|
| `-v` | Verbose test output |
| `-race` | Enable Go race detection |
| `./...` | Test all packages |

Do not use `sudo` for normal unit testing.

---

# 🧭 Recommended First Run

For a new user, the simplest workflow is:

### Step 1 — Install dependencies

```bash
sudo apt update && sudo apt install -y libpcap-dev git build-essential
```

### Step 2 — Clone

```bash
git clone https://github.com/cys-dexter/NetForensics.git
cd NetForensics
```

### Step 3 — Verify modules

```bash
go mod verify
```

### Step 4 — Build

```bash
rm -rf bin && mkdir -p bin
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

### Step 5 — Check the CLI

```bash
./bin/netforensics --help
```

### Step 6 — Analyze a PCAP

```bash
./bin/netforensics -r capture.pcap
```

### Step 7 — Or perform live capture

```bash
sudo ./bin/netforensics -i eth0
```

### Step 8 — Run tests

```bash
go test -v -race ./...
```

---

# 📁 Project Structure

The documented project follows a modular Go architecture:

```text
NetForensics/
├── cmd/
│   └── netforensics/
│       └── main.go
│
├── pkg/
│   ├── capture/
│   │   ├── capture.go
│   │   └── stats.go
│   │
│   ├── reassembly/
│   │   ├── stream.go
│   │   ├── carver.go
│   │   └── ftp.go
│   │
│   ├── forensics/
│   │   ├── engine.go
│   │   ├── models.go
│   │   ├── hasher.go
│   │   ├── dns_tunnel.go
│   │   ├── arp_poison.go
│   │   ├── port_scan.go
│   │   └── forensics_test.go
│   │
│   ├── protocols/
│   │   ├── parser.go
│   │   ├── types.go
│   │   ├── dns.go
│   │   ├── arp.go
│   │   ├── http.go
│   │   └── protocols_test.go
│   │
│   ├── reporter/
│   │   ├── timeline.go
│   │   ├── export_json.go
│   │   ├── export_csv.go
│   │   └── reporter_test.go
│   │
│   └── ui/
│       ├── tui.go
│       ├── views.go
│       └── keybindings.go
│
├── testdata/
│   ├── generate_pcaps.go
│   └── forensic_sample.pcap
│
├── bin/
│   └── netforensics
│
├── extracted_artifacts/
├── go.mod
├── go.sum
└── README.md
```

The existing project documentation identifies `cmd/netforensics/main.go` as the CLI entry point and separates capture, reassembly, forensics, protocols, reporting, and TUI functionality into dedicated packages.

---

# 🛡️ Investigation Workflow

A typical investigation can be performed as follows:

```text
PCAP / Live Interface
        │
        ▼
Packet Capture / Parsing
        │
        ├──► Protocol Analysis
        │
        ├──► Threat Detection
        │       ├── ARP Poisoning
        │       ├── Port Scanning
        │       └── DNS Tunneling
        │
        ├──► TCP Stream Reassembly
        │
        ├──► Artifact Carving
        │
        ├──► SHA-256 / MD5 Hashing
        │
        ▼
Forensic Timeline
        │
        ├──► JSON
        └──► CSV
```

This reflects the documented separation between packet ingestion, threat detection, artifact extraction, hashing, timeline generation, and reporting.

---

# ⚠️ Important Operational Notes

### Offline analysis

Offline PCAP analysis normally does not require root privileges:

```bash
./bin/netforensics -r capture.pcap
```

### Live capture

Live capture may require elevated privileges:

```bash
sudo ./bin/netforensics -i eth0
```

### Building

Do **not** build as root:

```bash
go build ...
```

not:

```bash
sudo go build ...
```

### Permission errors

If you previously used `sudo` during development:

```bash
sudo chown -R "$USER:$USER" .
```

Then clean and rebuild:

```bash
rm -rf bin && mkdir -p bin
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

---

# 👨‍💻 Developer

**Developer:** Ahmad

**GitHub:**  
https://github.com/cys-dexter

**Project:**  
NetForensics

**Version:**  
`1.0.0`

---

# 📜 License

NetForensics is distributed under the **MIT License**.

See the `LICENSE` file in the repository for the complete license text.

---

## ⚖️ Responsible Use

NetForensics is intended for **authorized security monitoring, network troubleshooting, digital forensics, and incident-response investigations**.

Only capture or analyze network traffic on systems and networks for which you have appropriate authorization.

---

# 🔍 Automated Binary Reputation Verification

NetForensics integrates automated binary reputation verification into the forensic artifact-analysis workflow.

## CIRCL Hashlookup Integration

NetForensics can query the **CIRCL Hashlookup** database in real time for carved binaries and executable artifacts.

This allows the forensic pipeline to verify whether an extracted executable is already known and associated with trusted software.

## SHA-256 Reputation Verification

For carved binary artifacts, NetForensics uses the calculated **SHA-256 hash** to perform reputation verification against known binary repositories.

The verification workflow helps distinguish known legitimate software from previously unknown or suspicious binaries.

## False Positive Reduction

When a carved binary matches a known legitimate software entry in the Hashlookup database, NetForensics can automatically reduce the associated threat classification.

This helps minimize false positives during forensic investigations while preserving the original artifact and its forensic metadata.

## Dynamic Threat Downgrading

If the SHA-256 hash of a carved binary matches a trusted known binary, its threat indicator is automatically downgraded to:

```text
LevelSafe
```

This allows known legitimate software to be separated from suspicious or unknown artifacts without removing it from the investigation results.

## Forensic Workflow

The automated reputation-verification workflow can be represented as:

```text
Network Traffic / PCAP
        │
        ▼
TCP Stream Reassembly
        │
        ▼
Artifact Carving
        │
        ▼
Executable Detected
        │
        ▼
SHA-256 Calculation
        │
        ▼
CIRCL Hashlookup Query
        │
        ├──► Trusted Known Binary
        │          │
        │          ▼
        │      LevelSafe
        │
        └──► No Trusted Match
                   │
                   ▼
          Continue Threat Analysis
```

This integration adds an additional reputation-verification layer to the existing artifact carving, hashing, threat detection, and forensic reporting workflow.
