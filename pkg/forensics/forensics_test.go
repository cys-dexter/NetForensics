// Unit tests for the forensics threat detection and hashing engines.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"net"
	"os"
	"testing"
	"time"

	"netforensics/pkg/protocols"
)

func TestCryptographicHashing(t *testing.T) {
	data := []byte("NetForensics DFIR Investigation Payload")
	hashes := ComputeHashes(data)

	if len(hashes.SHA256) != 64 {
		t.Fatalf("expected 64-char hex SHA-256, got: %s", hashes.SHA256)
	}
	if len(hashes.MD5) != 32 {
		t.Fatalf("expected 32-char hex MD5, got: %s", hashes.MD5)
	}

	// Verify file hashing
	tmpFile, err := os.CreateTemp("", "hash_test_*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	fileHashes, err := ComputeFileHashes(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to compute file hashes: %v", err)
	}

	if fileHashes.SHA256 != hashes.SHA256 {
		t.Errorf("file SHA256 %s != mem SHA256 %s", fileHashes.SHA256, hashes.SHA256)
	}
	if fileHashes.MD5 != hashes.MD5 {
		t.Errorf("file MD5 %s != mem MD5 %s", fileHashes.MD5, hashes.MD5)
	}
}

func TestDNSTunnelingDetection(t *testing.T) {
	detector := NewDNSTunnelDetector()
	now := time.Now()

	// 1. Normal benign query
	benignDNS := &protocols.DNSEvent{
		QueryName: "www.google.com",
		QueryType: "A",
	}
	alert := detector.InspectQuery("192.168.1.50", "8.8.8.8", benignDNS, now)
	if alert != nil {
		t.Errorf("expected no alert for benign DNS, got: %+v", alert)
	}

	// 2. High entropy Base32 / Hex tunneling query
	tunnelDNS := &protocols.DNSEvent{
		QueryName: "4d616c6963696f757344617461457866696c74726174696f6e.tunnel.c2server.org",
		QueryType: "TXT",
	}
	alert = detector.InspectQuery("192.168.1.100", "8.8.8.8", tunnelDNS, now)
	if alert == nil {
		t.Fatalf("expected alert for DNS tunneling query, got nil")
	}
	if alert.Level != LevelThreat && alert.Level != LevelWarning {
		t.Errorf("expected Threat/Warning level, got: %s", alert.Level)
	}
	if alert.Category != CategoryDNSTunneling {
		t.Errorf("expected CategoryDNSTunneling, got: %s", alert.Category)
	}
}

func TestARPPoisonDetection(t *testing.T) {
	detector := NewARPPoisonDetector()
	now := time.Now()

	gatewayIP := net.ParseIP("192.168.1.1")
	legitMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	attackerMAC, _ := net.ParseMAC("de:ad:be:ef:00:99")

	// 1. Legitimate gateway ARP announcement
	legitARP := &protocols.ARPEvent{
		Operation: "Reply",
		SenderIP:  gatewayIP,
		SenderMAC: legitMAC,
		TargetIP:  net.ParseIP("192.168.1.50"),
		TargetMAC: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	}
	alert := detector.InspectARP(legitARP, now)
	if alert != nil {
		t.Errorf("expected no alert for initial legit ARP, got: %+v", alert)
	}

	// 2. Poisoned ARP packet with attacker MAC claiming Gateway IP
	poisonARP := &protocols.ARPEvent{
		Operation:    "Reply",
		SenderIP:     gatewayIP,
		SenderMAC:    attackerMAC,
		TargetIP:     net.ParseIP("192.168.1.50"),
		TargetMAC:    net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		IsGratuitous: true,
	}
	alert = detector.InspectARP(poisonARP, now.Add(time.Second))
	if alert == nil {
		t.Fatalf("expected ARP poisoning threat alert, got nil")
	}
	if alert.Level != LevelThreat {
		t.Errorf("expected LevelThreat, got: %s", alert.Level)
	}
	if alert.Category != CategoryARPPoisoning {
		t.Errorf("expected CategoryARPPoisoning, got: %s", alert.Category)
	}
}

func TestPortScanDetection(t *testing.T) {
	detector := NewPortScanDetector()
	now := time.Now()

	// 1. Xmas scan test (FIN+PSH+URG)
	flow := protocols.FlowKey{
		SrcIP:   "10.0.0.99",
		DstIP:   "10.0.0.1",
		SrcPort: 54321,
		DstPort: 80,
		Proto:   "TCP",
	}
	xmasFlags := protocols.TCPFlagInfo{
		IsTCP: true,
		FIN:   true,
		PSH:   true,
		URG:   true,
	}
	alert := detector.InspectTCP(flow, xmasFlags, now)
	if alert == nil {
		t.Fatalf("expected alert for TCP Xmas scan, got nil")
	}
	if alert.Level != LevelThreat {
		t.Errorf("expected LevelThreat, got: %s", alert.Level)
	}

	// 2. Null scan test (no flags)
	nullFlags := protocols.TCPFlagInfo{
		IsTCP: true,
	}
	alert = detector.InspectTCP(flow, nullFlags, now)
	if alert == nil {
		t.Fatalf("expected alert for TCP Null scan, got nil")
	}

	// 3. Multi-port rapid sweep
	srcIP := "10.0.0.77"
	var sweepAlert *ThreatAlert
	for port := uint16(1); port <= 15; port++ {
		synFlow := protocols.FlowKey{
			SrcIP:   srcIP,
			DstIP:   "10.0.0.10",
			SrcPort: 40000 + port,
			DstPort: port,
			Proto:   "TCP",
		}
		synFlags := protocols.TCPFlagInfo{
			IsTCP:  true,
			SYN:    true,
			Window: 65535,
		}
		res := detector.InspectTCP(synFlow, synFlags, now.Add(time.Duration(port)*time.Millisecond))
		if res != nil {
			sweepAlert = res
			break
		}
	}

	if sweepAlert == nil {
		t.Fatalf("expected multi-port sweep alert after contacting 15 distinct ports")
	}
	if sweepAlert.Category != CategoryPortScanning {
		t.Errorf("expected CategoryPortScanning, got: %s", sweepAlert.Category)
	}
}
