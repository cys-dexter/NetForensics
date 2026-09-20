// Package forensics provides ARP spoofing and Man-in-the-Middle (MITM) anomaly detection.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"netforensics/pkg/protocols"
)

// ARPEntry models a learned IP-to-MAC hardware binding.
type ARPEntry struct {
	IP        string
	MAC       string
	FirstSeen time.Time
	LastSeen  time.Time
	Hits      uint64
	Changes   int
}

// ARPPoisonDetector maintains an in-memory ARP table to catch MITM cache poisoning attacks.
type ARPPoisonDetector struct {
	mu          sync.RWMutex
	table       map[string]*ARPEntry
	macHistory  map[string][]string // IP -> list of observed MACs
	gratuitousCount map[string]int  // MAC -> gratuitous ARP count
}

// NewARPPoisonDetector constructs the ARP forensic engine.
func NewARPPoisonDetector() *ARPPoisonDetector {
	return &ARPPoisonDetector{
		table:           make(map[string]*ARPEntry),
		macHistory:      make(map[string][]string),
		gratuitousCount: make(map[string]int),
	}
}

// InspectARP analyzes an ARP event against historical bindings to spot poisoning attempts.
func (d *ARPPoisonDetector) InspectARP(arpEv *protocols.ARPEvent, timestamp time.Time) *ThreatAlert {
	if arpEv == nil || arpEv.SenderIP == nil || arpEv.SenderMAC == nil {
		return nil
	}

	ipStr := arpEv.SenderIP.String()
	macStr := arpEv.SenderMAC.String()

	// Ignore link-local and unspecified 0.0.0.0 (e.g. DHCP discovery probes)
	if ipStr == "0.0.0.0" || isIgnoredIP(arpEv.SenderIP) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, exists := d.table[ipStr]
	if !exists {
		// First time observing this IP
		d.table[ipStr] = &ARPEntry{
			IP:        ipStr,
			MAC:       macStr,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
			Hits:      1,
			Changes:   0,
		}
		d.macHistory[ipStr] = []string{macStr}

		if arpEv.IsGratuitous {
			d.gratuitousCount[macStr]++
		}
		return nil
	}

	// Update existing record
	existing.LastSeen = timestamp
	existing.Hits++

	// Check for MAC Conflict / Cache Poisoning
	if !strings.EqualFold(existing.MAC, macStr) {
		existing.Changes++
		d.macHistory[ipStr] = append(d.macHistory[ipStr], macStr)

		prevMAC := existing.MAC
		existing.MAC = macStr // Update to latest observed

		evidence := fmt.Sprintf("IP %s was originally bound to MAC %s (seen %d times), but is now announced by MAC %s (Operation: %s)",
			ipStr, prevMAC, existing.Hits, macStr, arpEv.Operation)

		if arpEv.IsGratuitous {
			evidence += "; Unsolicited Gratuitous ARP packet observed"
		}

		if existing.Changes >= 2 {
			evidence += fmt.Sprintf("; Severe MAC-Flapping detected (%d alterations on same IP)", existing.Changes)
		}

		return &ThreatAlert{
			ID:         fmt.Sprintf("ARP-MITM-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryARPPoisoning,
			Title:      "ARP Cache Poisoning / MITM Attack Detected",
			SourceIP:   ipStr,
			DestIP:     arpEv.TargetIP.String(),
			Protocol:   "ARP",
			Details:    fmt.Sprintf("Conflict detected on host %s: Ownership claimed by illegitimate MAC %s", ipStr, macStr),
			Evidence:   evidence,
			Confidence: 0.95,
		}
	}

	// Check for excessive unsolicited gratuitous ARP announcements
	if arpEv.IsGratuitous {
		d.gratuitousCount[macStr]++
		if d.gratuitousCount[macStr] > 10 {
			return &ThreatAlert{
				ID:         fmt.Sprintf("ARP-GRAT-%d", timestamp.UnixNano()),
				Timestamp:  timestamp,
				Level:      LevelWarning,
				Category:   CategoryARPPoisoning,
				Title:      "Anomalous Gratuitous ARP Storm Detected",
				SourceIP:   ipStr,
				DestIP:     "Broadcast",
				Protocol:   "ARP",
				Details:    fmt.Sprintf("High volume of Gratuitous ARP packets (%d) originating from MAC %s", d.gratuitousCount[macStr], macStr),
				Evidence:   fmt.Sprintf("Host %s [%s] is repeatedly broadcasting Gratuitous ARP replies", ipStr, macStr),
				Confidence: 0.70,
			}
		}
	}

	return nil
}

func isIgnoredIP(ip net.IP) bool {
	return ip.IsMulticast() || ip.IsUnspecified()
}
