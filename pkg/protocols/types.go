// Package protocols defines data models and protocol decoders for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package protocols

import (
	"net"
	"time"
)

// SeverityLevel indicates the threat level of an observed network anomaly.
type SeverityLevel string

const (
	SeveritySafe    SeverityLevel = "SAFE"            // 🟢 Normal operational baseline
	SeverityWarning SeverityLevel = "WARNING"         // 🟡 Anomalous behavior or reconnaissance
	SeverityThreat  SeverityLevel = "THREAT_DETECTED" // 🔴 Active attack or confirmed exploitation
)

// Badge returns a graphical color-coded badge indicator for the severity level.
func (s SeverityLevel) Badge() string {
	switch s {
	case SeveritySafe:
		return "🟢 Safe"
	case SeverityWarning:
		return "🟡 Warning"
	case SeverityThreat:
		return "🔴 Threat Detected"
	default:
		return "⚪ Unknown"
	}
}

// DNSEvent encapsulates decoded DNS query and response details.
type DNSEvent struct {
	ID           uint16
	QR           bool // false = Query, true = Response
	OpCode       string
	ResponseCode string
	QueryName    string
	QueryType    string
	Questions    []DNSQuestion
	Answers      []string
	TTL          uint32
}

// DNSQuestion represents a single query inside a DNS packet.
type DNSQuestion struct {
	Name  string
	Type  string
	Class string
}

// ARPEvent encapsulates decoded ARP packet details.
type ARPEvent struct {
	Operation    string // "Request" or "Reply"
	SenderIP     net.IP
	SenderMAC    net.HardwareAddr
	TargetIP     net.IP
	TargetMAC    net.HardwareAddr
	IsGratuitous bool
}

// PacketSummary encapsulates decoded Layer 2 to Layer 7 metadata for UI display.
type PacketSummary struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Protocol  string    `json:"protocol"`
	Length    int       `json:"length"`
	Info      string    `json:"info"`
}

// TimelineEvent records a chronological event in the forensic audit ledger.
type TimelineEvent struct {
	Timestamp   time.Time     `json:"timestamp"`
	Type        string        `json:"type"` // SYSTEM, PACKET, THREAT, CARVED_FILE
	Severity    SeverityLevel `json:"severity"`
	Summary     string        `json:"summary"`
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Details     string        `json:"details"`
	EvidenceRef string        `json:"evidence_ref,omitempty"`
}
