// Package forensics provides threat detection, IOC analysis, cryptographic hashing, and artifact tracking.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"time"
)

// ThreatLevel defines the severity classification of detected anomalies.
type ThreatLevel string

const (
	LevelSafe    ThreatLevel = "🟢 Safe"
	LevelWarning ThreatLevel = "🟡 Warning"
	LevelThreat  ThreatLevel = "🔴 Threat Detected"
)

// Badge returns the visual badge string for the threat level.
func (l ThreatLevel) Badge() string {
	return string(l)
}

// ThreatCategory identifies the attack vector or anomalous behavior.
type ThreatCategory string

const (
	CategoryDNSTunneling    ThreatCategory = "DNS Tunneling / Exfiltration"
	CategoryARPPoisoning    ThreatCategory = "ARP Poisoning / MITM"
	CategoryPortScanning    ThreatCategory = "Port Scanning / Reconnaissance"
	CategoryTCPAnomaly      ThreatCategory = "Abnormal TCP Flag Anomaly"
	CategoryMaliciousPayload ThreatCategory = "Suspicious Executable / Payload"
)

// ThreatAlert encapsulates a detected security event with forensic evidence.
type ThreatAlert struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Level       ThreatLevel    `json:"level"`
	Category    ThreatCategory `json:"category"`
	Title       string         `json:"title"`
	SourceIP    string         `json:"source_ip"`
	DestIP      string         `json:"dest_ip"`
	Protocol    string         `json:"protocol"`
	Details     string         `json:"details"`
	Evidence    string         `json:"evidence"`
	Confidence  float64        `json:"confidence"` // 0.0 to 1.0
}

// ArtifactRecord catalogs carved files and payloads extracted from streams.
type ArtifactRecord struct {
	ID              string      `json:"id"`
	Filename        string      `json:"filename"`
	FilePath        string      `json:"file_path"`
	SizeBytes       int64       `json:"size_bytes"`
	MIMEType        string      `json:"mime_type"`
	SHA256          string      `json:"sha256"`
	MD5             string      `json:"md5"`
	SourceIP        string      `json:"source_ip"`
	DestIP          string      `json:"dest_ip"`
	SourcePort      uint16      `json:"source_port"`
	DestPort        uint16      `json:"dest_port"`
	Protocol        string      `json:"protocol"`
	Timestamp       time.Time   `json:"timestamp"`
	ThreatIndicator ThreatLevel `json:"threat_indicator"`
}
