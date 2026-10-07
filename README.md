# NetForensics

**Enterprise Network Forensics & PCAP Artifact Collector | DFIR Investigation Suite**

NetForensics is an enterprise-oriented **Network Forensics and Digital Forensics & Incident Response (DFIR)** tool written in **Go (Golang)**.

It is designed for security analysts, incident responders, and network investigators who need to analyze captured network traffic, investigate suspicious activity, detect common network attacks, extract forensic artifacts, and generate structured investigation reports.

NetForensics supports both **offline PCAP/PCAPNG analysis** and **live network packet capture**.

---

## 🔑 Key Features

- **Offline PCAP Analysis**
  - Analyze existing `.pcap` and `.pcapng` network captures.
  - Inspect captured network traffic without requiring live packet capture.

- **Threat Detection**
  - Detect potential **ARP Poisoning / ARP Cache Poisoning**.
  - Identify suspicious **Man-in-the-Middle (MITM)** activity.
  - Detect **TCP Port Scanning** patterns.
  - Detect suspicious **DNS Tunneling** and possible data-exfiltration patterns.

- **Artifact Carving**
  - Extract files and payloads from captured network traffic.
  - Reassemble relevant TCP streams.
  - Identify extracted files using file signatures / magic bytes.
  - Store extracted evidence in the `extracted_artifacts/` directory.

- **Forensic Hashing**
  - Generate SHA-256 hashes for extracted artifacts.
  - Generate MD5 hashes for artifact identification and verification.

- **Forensic Timeline**
  - Track packets, alerts, and extracted artifacts chronologically.
  - Support structured evidence and investigation workflows.

- **Report Export**
  - Export forensic data as **JSON**.
  - Export forensic timelines as **CSV**.

- **Live Network Capture**
  - Capture packets directly from a selected network interface.
  - Designed for authorized network monitoring and DFIR investigations.

---

## 📋 Prerequisites

Before installing NetForensics, make sure the following requirements are installed.

### Go

NetForensics requires:

**Go 1.22 or newer**

Check your installed version:

```bash
go version
```

Example:

```text
go version go1.22.x linux/amd64
```

If your Go version is older than 1.22, upgrade Go before building the project.

---

### libpcap

Live packet capture requires the `libpcap` development library.

For **Ubuntu / Debian**, install it with:

```bash
sudo apt install -y libpcap-dev
```

It is recommended to install the package before attempting to build NetForensics.

---

## 🛠️ Installation & Build

Follow the steps below **in the exact order**.

> ### ⚠️ Important: Do NOT use `sudo` with `go build`
>
> Do **not** build the project using:
>
> ```bash
> sudo go build ...
> ```
>
> Running Go build commands with `sudo` can create root-owned files inside the project directory, especially inside `bin/`, which can later result in errors such as:
>
> ```text
> permission denied
> ```
>
> The correct approach is to perform the build as your normal user and use `sudo` only when administrative privileges are actually required, such as installing system packages or performing live packet capture.

### 1. Clone the Repository

```bash
git clone https://github.com/cys-dexter/NetForensics.git
```

Enter the project directory:

```bash
cd NetForensics
```

---

### 2. Fix Project Ownership

If the project directory or files were previously created using `sudo`, some files may belong to `root`.

To make sure the current user owns the project:

```bash
sudo chown -R $USER:$USER .
```

This is especially useful if you previously encountered:

```text
Permission denied
```

when trying to remove or overwrite files inside the project.

Verify ownership with:

```bash
ls -la
```

The project files should be owned by your current user.

---

### 3. Verify Go Dependencies

Run:

```bash
go mod verify
```

This verifies that the downloaded Go modules match their expected checksums.

If the verification succeeds, continue to the build step.

---

### 4. Recreate the Binary Directory

Remove any existing `bin` directory and create a clean one:

```bash
rm -rf bin && mkdir -p bin
```

Because ownership was fixed in the previous step, this command should run without requiring `sudo`.

---

### 5. Build NetForensics

Build the optimized executable:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

**Do not add `sudo` to this command.**

Correct:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

Incorrect:

```bash
sudo go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

After a successful build, the executable will be located at:

```text
bin/netforensics
```

You can verify it with:

```bash
ls -lh bin/netforensics
```

---

## 🚨 Troubleshooting Permissions

### `Permission denied` when creating `bin/netforensics`

If you receive an error similar to:

```text
open bin/netforensics: permission denied
```

or:

```text
cannot create bin/netforensics: Permission denied
```

first fix the ownership:

```bash
sudo chown -R $USER:$USER .
```

Then recreate the binary directory:

```bash
rm -rf bin && mkdir -p bin
```

Finally rebuild **without `sudo`**:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

---

### `bin` is owned by root

Check the directory:

```bash
ls -ld bin
```

If the owner is `root`, fix it with:

```bash
sudo chown -R $USER:$USER bin
```

Then build normally:

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

---

### General rule for permissions

Use `sudo` for administrative operations such as:

```bash
sudo apt install -y libpcap-dev
```

and live packet capture:

```bash
sudo ./bin/netforensics -i eth0
```

Do **not** normally use `sudo` for:

```bash
go mod verify
go test -v -race ./...
go build ...
```

This keeps generated files owned by your normal user and prevents recurring permission problems.

---

## 🚀 Usage

After successfully building the project, the executable can be used for offline PCAP analysis or live network capture.

### Display Help

Display the available command-line options:

```bash
./bin/netforensics --help
```

---

### Analyze a PCAP File

Analyze an existing PCAP file:

```bash
./bin/netforensics -r /path/to/capture.pcap
```

Example:

```bash
./bin/netforensics -r suspicious_traffic.pcap
```

For a PCAPNG capture:

```bash
./bin/netforensics -r suspicious_traffic.pcapng
```

This mode does not require root privileges because the tool is reading an existing capture file rather than directly accessing a live network interface.

---

### Live Network Capture

Live packet capture may require root privileges depending on the system configuration.

Run:

```bash
sudo ./bin/netforensics -i eth0
```

Replace `eth0` with the actual interface on your system.

To list available network interfaces on Linux:

```bash
ip link
```

Common examples include:

```text
eth0
ens33
enp0s3
wlan0
```

Then select the appropriate interface:

```bash
sudo ./bin/netforensics -i wlan0
```

> **Note:** Only capture traffic on networks and systems where you have authorization to perform monitoring or forensic analysis.

---

## 🧪 Running Tests

Run the complete Go test suite with the race detector:

```bash
go test -v -race ./...
```

### What the options mean

- `-v` — Displays detailed test output.
- `-race` — Enables Go's race detector.
- `./...` — Runs tests across all project packages.

Do not run the tests with `sudo` unless there is a specific, documented test that requires elevated privileges.

---

## 📁 Generated Artifacts

Extracted forensic artifacts are stored in:

```text
./extracted_artifacts/
```

Depending on the investigation and captured traffic, the project may produce:

- Extracted files
- Artifact hashes
- Threat alerts
- Timeline events
- JSON reports
- CSV reports

The original project also provides structured forensic timeline and artifact processing capabilities.

---

## 🔎 Typical Workflow

A new user can follow this workflow from start to finish.

### 1. Install the required system dependency

```bash
sudo apt install -y libpcap-dev
```

### 2. Clone the project

```bash
git clone https://github.com/cys-dexter/NetForensics.git
cd NetForensics
```

### 3. Fix ownership if necessary

```bash
sudo chown -R $USER:$USER .
```

### 4. Verify dependencies

```bash
go mod verify
```

### 5. Prepare the binary directory

```bash
rm -rf bin && mkdir -p bin
```

### 6. Build without sudo

```bash
go build -ldflags="-s -w" -buildvcs=false -o bin/netforensics ./cmd/netforensics
```

### 7. Verify the executable

```bash
./bin/netforensics --help
```

### 8. Analyze a PCAP

```bash
./bin/netforensics -r /path/to/capture.pcap
```

### 9. Or perform live capture

```bash
sudo ./bin/netforensics -i eth0
```

### 10. Run the test suite

```bash
go test -v -race ./...
```

---

## 👨‍💻 Developer

**Developer:** Ahmad

**GitHub:**  
https://github.com/cys-dexter

**Repository:**  
https://github.com/cys-dexter/NetForensics

---

## 📜 License

NetForensics is distributed under the **MIT License**.

See the `LICENSE` file in the repository for the complete license text.
