// Package forensics provides port scanning, reconnaissance, and TCP flag anomaly detection.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"netforensics/pkg/protocols"
)

// scanActivity tracks port access events from a single source host.
type scanActivity struct {
	firstSeen   time.Time
	lastSeen    time.Time
	targetPorts map[uint16]time.Time
	targetHosts map[string]bool
	synCount    int
	xmasCount   int
	nullCount   int
	finCount    int
}

// PortScanDetector analyzes TCP flag patterns and rapid multi-port connection attempts.
type PortScanDetector struct {
	mu           sync.Mutex
	activity     map[string]*scanActivity // Source IP -> Activity
	scanPortThresh int                   // Unique ports required to flag a port scan
	timeWindow   time.Duration
}

// NewPortScanDetector initializes the port reconnaissance detection engine.
func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		activity:       make(map[string]*scanActivity),
		scanPortThresh: 12,
		timeWindow:     15 * time.Second,
	}
}

// InspectTCP analyzes TCP headers for flag anomalies and port sweep behavior.
func (d *PortScanDetector) InspectTCP(flow protocols.FlowKey, flags protocols.TCPFlagInfo, timestamp time.Time) *ThreatAlert {
	if !flags.IsTCP || flow.SrcIP == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	act, exists := d.activity[flow.SrcIP]
	if !exists {
		act = &scanActivity{
			firstSeen:   timestamp,
			lastSeen:    timestamp,
			targetPorts: make(map[uint16]time.Time),
			targetHosts: make(map[string]bool),
		}
		d.activity[flow.SrcIP] = act
	}

	// Purge stale port entries beyond sliding window
	for p, t := range act.targetPorts {
		if timestamp.Sub(t) > d.timeWindow {
			delete(act.targetPorts, p)
		}
	}

	act.lastSeen = timestamp
	act.targetPorts[flow.DstPort] = timestamp
	act.targetHosts[flow.DstIP] = true

	// 1. Inspect TCP Flag Combinations for RFC-Violating Stealth Scans
	// Xmas Tree Scan: FIN + PSH + URG set simultaneously
	if flags.FIN && flags.PSH && flags.URG && !flags.SYN && !flags.ACK {
		act.xmasCount++
		return &ThreatAlert{
			ID:         fmt.Sprintf("TCP-XMAS-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryPortScanning,
			Title:      "TCP Xmas Tree Stealth Scan Detected (Nmap -sX)",
			SourceIP:   flow.SrcIP,
			DestIP:     flow.DstIP,
			Protocol:   "TCP",
			Details:    fmt.Sprintf("Host %s probed %s:%d with illegal FIN+PSH+URG flag combination", flow.SrcIP, flow.DstIP, flow.DstPort),
			Evidence:   "Flags: [FIN, PSH, URG] without SYN/ACK; Classic RFC 793 evasion signature",
			Confidence: 0.98,
		}
	}

	// Null Scan: All control flags cleared
	if !flags.SYN && !flags.ACK && !flags.FIN && !flags.RST && !flags.PSH && !flags.URG {
		act.nullCount++
		return &ThreatAlert{
			ID:         fmt.Sprintf("TCP-NULL-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryPortScanning,
			Title:      "TCP Null Scan Detected (Nmap -sN)",
			SourceIP:   flow.SrcIP,
			DestIP:     flow.DstIP,
			Protocol:   "TCP",
			Details:    fmt.Sprintf("Host %s probed %s:%d with zero TCP flags set", flow.SrcIP, flow.DstIP, flow.DstPort),
			Evidence:   "Flags: [None]; Illegal packet attempting to solicit RST response",
			Confidence: 0.98,
		}
	}

	// FIN Scan: Solely FIN flag without ACK or preceding handshake
	if flags.FIN && !flags.SYN && !flags.ACK && !flags.RST && !flags.PSH && !flags.URG {
		act.finCount++
		return &ThreatAlert{
			ID:         fmt.Sprintf("TCP-FIN-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryPortScanning,
			Title:      "TCP FIN Stealth Scan Detected (Nmap -sF)",
			SourceIP:   flow.SrcIP,
			DestIP:     flow.DstIP,
			Protocol:   "TCP",
			Details:    fmt.Sprintf("Host %s probed %s:%d with lone FIN flag", flow.SrcIP, flow.DstIP, flow.DstPort),
			Evidence:   "Flags: [FIN]; Out-of-state teardown frame testing for open port",
			Confidence: 0.95,
		}
	}

	// SYN Scan Tracker
	if flags.SYN && !flags.ACK {
		act.synCount++

		// Masscan Fingerprint Signature: default window size is precisely 1024
		if flags.Window == 1024 {
			return &ThreatAlert{
				ID:         fmt.Sprintf("MASSCAN-%d", timestamp.UnixNano()),
				Timestamp:  timestamp,
				Level:      LevelThreat,
				Category:   CategoryPortScanning,
				Title:      "High-Speed Masscan Fingerprint Detected",
				SourceIP:   flow.SrcIP,
				DestIP:     flow.DstIP,
				Protocol:   "TCP",
				Details:    fmt.Sprintf("Masscan scanner signature matched against host %s targeting port %d", flow.SrcIP, flow.DstPort),
				Evidence:   "TCP SYN with static window size 1024 (characteristic of Robert Graham Masscan)",
				Confidence: 0.90,
			}
		}
	}

	// 2. Multi-Port Rapid Connection Heuristic
	uniquePorts := len(act.targetPorts)
	if uniquePorts >= d.scanPortThresh {
		// Prepare port sample string
		portSamples := []string{}
		for p := range act.targetPorts {
			if len(portSamples) < 6 {
				portSamples = append(portSamples, fmt.Sprintf("%d", p))
			}
		}

		// Reset ports to prevent repetitive alerts on every subsequent packet
		act.targetPorts = make(map[uint16]time.Time)

		return &ThreatAlert{
			ID:         fmt.Sprintf("SCAN-BURST-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryPortScanning,
			Title:      "Rapid TCP Port Sweep / Reconnaissance Detected",
			SourceIP:   flow.SrcIP,
			DestIP:     flow.DstIP,
			Protocol:   "TCP",
			Details:    fmt.Sprintf("Source %s contacted %d distinct destination ports in %v", flow.SrcIP, uniquePorts, d.timeWindow),
			Evidence:   fmt.Sprintf("Sampled probed ports: [%s...]; Target hosts: %d; SYN probes: %d", strings.Join(portSamples, ", "), len(act.targetHosts), act.synCount),
			Confidence: 0.92,
		}
	}

	return nil
}
