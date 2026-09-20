// Package protocols_test contains unit tests for protocol decoders.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package protocols_test

import (
	"net"
	"testing"

	"netforensics/pkg/protocols"

	"github.com/google/gopacket/layers"
)

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		fqdn     string
		expected string
	}{
		{"cys-dexter.github.io", "cys-dexter"},
		{"malicious.exfil.data.corp.com.", "malicious.exfil.data"},
		{"evil.com", ""},
		{"internal.co.uk", "internal"},
		{"a.b.c.d.example.com", "a.b.c.d"},
	}

	for _, tt := range tests {
		result := protocols.ExtractSubdomain(tt.fqdn)
		if result != tt.expected {
			t.Errorf("ExtractSubdomain(%q) = %q; expected %q", tt.fqdn, result, tt.expected)
		}
	}
}

func TestCalculateShannonEntropy(t *testing.T) {
	// Zero entropy test (repeated char)
	zeroEntropy := protocols.CalculateShannonEntropy("aaaaaaaaaa")
	if zeroEntropy != 0.0 {
		t.Errorf("expected 0.0 entropy for repeated string, got %f", zeroEntropy)
	}

	// Normal word entropy
	englishEntropy := protocols.CalculateShannonEntropy("normal-web-request")
	if englishEntropy < 2.0 || englishEntropy > 3.8 {
		t.Errorf("unexpected entropy for normal word: %f", englishEntropy)
	}

	// High entropy base64 / hex string
	highEntropy := protocols.CalculateShannonEntropy("a9f8b7c6d5e41230abcdef")
	if highEntropy < 3.5 {
		t.Errorf("expected high entropy (>3.5) for hex payload, got %f", highEntropy)
	}
}

func TestParseARP(t *testing.T) {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SourceProtAddress: []byte{192, 168, 1, 1},
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    []byte{192, 168, 1, 1},
	}

	info := protocols.ParseARP(arp)
	if info == nil {
		t.Fatalf("ParseARP returned nil")
	}

	if !info.IsGratuitous {
		t.Errorf("Expected IsGratuitous to be true for broadcast ARP reply / same IP")
	}
	if !info.SenderIP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("Expected SenderIP 192.168.1.1, got %v", info.SenderIP)
	}
	if info.Operation != "Reply" {
		t.Errorf("Expected Operation Reply, got %s", info.Operation)
	}
}
