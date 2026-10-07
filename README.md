# NetForensics

**Enterprise Network Forensics & PCAP Artifact Collector | DFIR Investigation Suite**

NetForensics is an enterprise-oriented **Network Forensics and Digital Forensics & Incident Response (DFIR)** tool built with **Go (Golang)**.

The project is designed for security analysts, incident responders, and network investigators who need to inspect network traffic, analyze PCAP/PCAPNG captures, identify suspicious activity, extract forensic artifacts, and generate structured investigation reports.

NetForensics supports both **offline PCAP analysis** and **live network packet capture**, providing a practical workflow for network security investigations.

---

## 🔑 Key Features

- **PCAP / PCAPNG Analysis**
  - Analyze captured network traffic offline.
  - Support live packet capture through a network interface.
  - Inspect network protocols and traffic flows.

- **Threat Detection**
  - Detect potential **ARP Poisoning / ARP Cache Poisoning** attacks.
  - Identify suspicious **Man-in-the-Middle (MITM)** activity.
  - Detect multiple forms of **TCP Port Scanning**, including:
    - SYN scanning
    - FIN scanning
    - NULL scanning
    - Xmas Tree scanning
  - Detect rapid horizontal and vertical port sweeps.
  - Inspect suspicious DNS activity and possible DNS tunneling patterns.

- **Forensic Artifact Extraction**
  - Reassemble TCP streams.
  - Extract transferred files and network payloads.
  - Identify artifacts using file signatures / magic bytes.
  - Store extracted evidence in the `extracted_artifacts/` directory.

- **Cryptographic Hashing**
  - Calculate **SHA-256** hashes for extracted artifacts.
  - Calculate **MD5** hashes for forensic identification and verification.
  - Support evidence integrity tracking.

- **Forensic Timeline**
  - Organize network events chronologically.
  - Correlate alerts, packets, and extracted artifacts.
  - Export investigation data for further analysis.

- **Report Export**
  - Export forensic information to **JSON**.
  - Export timeline information to **CSV**.
  - Suitable for further processing in SIEM and forensic workflows.

- **Terminal Interface**
  - Interactive terminal-based analysis.
  - Live packet and alert monitoring.
  - Artifact and forensic timeline inspection.

---

## 📋 Prerequisites

Before installing NetForensics, make sure the required software and libraries are installed.

### 1. Go

NetForensics requires:

- **Go 1.22 or newer**

Verify your installed Go version:

```bash
go version
```

You should see a version equivalent to:

```text
go version go1.22.x ...
```

or newer.

If Go is not installed, install it before continuing.

### 2. libpcap Development Library

NetForensics uses packet-capture functionality that requires the `libpcap` development libraries.

On **Ubuntu / Debian**, install them with:

```bash
sudo apt install -y libpcap-dev
```

After installation, verify that the development environment is available before building the project.

---

## 🛠️ Installation & Build

Follow these steps in order.

### 1. Clone the Repository

```bash
git clone https://github.com/cys-dexter/NetForensics.git
```

### 2. Enter the Project Directory

```bash
cd NetForensics
```

### 3. Verify Go Dependencies

Run:

```bash
go mod verify
```

This verifies the downloaded Go module dependencies against their expected checksums.

### 4. Recreate the Binary Directory

If an old `bin` directory exists, remove it first:

```bash
sudo rm -rf bin && mkdir -p bin
```

This also helps prevent build problems caused by an old binary directory with incorrect permissions.

### 5. Build NetForensics

Build the production binary using:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

If the build completes successfully, the executable will be available at:

```text
bin/netforensics
```

Verify that the binary exists:

```bash
ls -lh bin/netforensics
```

> **Permission note:** Do not normally run the build itself with `sudo`. The command above removes a potentially root-owned `bin` directory and then recreates it so that the resulting binary can be owned by your normal user account.

---

## 🚀 Usage

After successfully building the project, the NetForensics binary can be used for offline PCAP analysis or live network capture.

### Display Help

To display all available command-line options:

```bash
./bin/netforensics --help
```

Use this command whenever you need to check available options or parameters.

---

### Analyze an Offline PCAP File

To analyze an existing PCAP/PCAPNG capture:

```bash
./bin/netforensics -r <path_to_pcap>
```

Example:

```bash
./bin/netforensics -r capture.pcap
```

Another example using a PCAPNG file:

```bash
./bin/netforensics -r capture.pcapng
```

This mode is useful for investigating previously captured network traffic without requiring a live network interface.

---

### Live Capture

To capture packets directly from a network interface:

```bash
sudo ./bin/netforensics -i <interface>
```

Example:

```bash
sudo ./bin/netforensics -i eth0
```

The `sudo` prefix is required for live packet capture when the current user does not have the necessary permissions to access the network capture interface.

To identify available network interfaces on Linux, you can use:

```bash
ip link
```

Then select the appropriate interface, such as:

```text
eth0
```

or:

```text
wlan0
```

and pass it to NetForensics:

```bash
sudo ./bin/netforensics -i wlan0
```

> **Important:** Replace `<interface>` with the actual network interface available on your system.

---

## 🧪 Running Tests

NetForensics includes Go tests for validating project functionality.

Run the complete test suite with:

```bash
go test -v -race ./...
```

The `-v` option enables verbose test output, while `-race` enables Go's race detector to help identify potential data races during concurrent execution.

A successful test run should complete without test failures or race-detection errors.

---

## 📁 Project Output

During forensic investigations, extracted artifacts are stored in:

```text
./extracted_artifacts/
```

The project can also generate structured forensic information such as:

```text
JSON
CSV
```

These outputs can be used for investigation documentation, evidence processing, SIEM ingestion, and further forensic analysis.

---

## 🔍 Typical Investigation Workflow

A basic NetForensics investigation can follow this workflow:

### Step 1 — Build the Tool

```bash
git clone https://github.com/cys-dexter/NetForensics.git
cd NetForensics
go mod verify
sudo rm -rf bin && mkdir -p bin
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

### Step 2 — Verify the Installation

```bash
./bin/netforensics --help
```

### Step 3 — Analyze a PCAP

```bash
./bin/netforensics -r capture.pcap
```

### Step 4 — Or Start Live Capture

```bash
sudo ./bin/netforensics -i eth0
```

### Step 5 — Run Tests

```bash
go test -v -race ./...
```

---

## 👨‍💻 Developer

**Developer:** Ahmad

**GitHub:**  
https://github.com/cys-dexter

**Project:**  
https://github.com/cys-dexter/NetForensics

---

## 📜 License

NetForensics is distributed under the **MIT License**.

See the `LICENSE` file in the repository for the complete license text.
