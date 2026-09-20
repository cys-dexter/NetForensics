// Package main generates realistic synthetic PCAP files for testing NetForensics DFIR capabilities.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	outPath := "testdata/forensic_sample.pcap"
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write pcap header: %v\n", err)
		os.Exit(1)
	}

	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	writePacket := func(ts time.Time, layerList ...gopacket.SerializableLayer) {
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, opts, layerList...); err != nil {
			fmt.Fprintf(os.Stderr, "Serialize error: %v\n", err)
			return
		}
		ci := gopacket.CaptureInfo{
			Timestamp:      ts,
			CaptureLength:  len(buf.Bytes()),
			Length:         len(buf.Bytes()),
			InterfaceIndex: 0,
		}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "WritePacket error: %v\n", err)
		}
	}

	// 1. Scenario: Benign DNS Query & Response
	ethDNS := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x11, 0x22, 0x33},
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipDNS := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4(192, 168, 1, 100),
		DstIP:    net.IPv4(8, 8, 8, 8),
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
	}
	udpDNS := &layers.UDP{
		SrcPort: 53531,
		DstPort: 53,
	}
	udpDNS.SetNetworkLayerForChecksum(ipDNS)
	dnsBenign := &layers.DNS{
		ID:     0x1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("www.company-portal.internal"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	writePacket(now, ethDNS, ipDNS, udpDNS, dnsBenign)

	// 2. Scenario: Malicious High-Entropy DNS Tunneling & Exfiltration (Cobalt Strike / Iodine Pattern)
	now = now.Add(100 * time.Millisecond)
	dnsTunnel := &layers.DNS{
		ID:     0x5678,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("4d616c6963696f757344617461457866696c74726174696f6e.tunnel.c2server.org"),
				Type:  layers.DNSTypeTXT,
				Class: layers.DNSClassIN,
			},
		},
	}
	writePacket(now, ethDNS, ipDNS, udpDNS, dnsTunnel)

	// 3. Scenario: Legitimate ARP Announcement
	now = now.Add(200 * time.Millisecond)
	ethARP1 := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLegit := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte{0x00, 0x50, 0x56, 0xc0, 0x00, 0x01},
		SourceProtAddress: []byte{192, 168, 1, 1},
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    []byte{192, 168, 1, 1},
	}
	writePacket(now, ethARP1, arpLegit)

	// 4. Scenario: ARP Cache Poisoning / MITM Attack (Attacker MAC claims Gateway 192.168.1.1)
	now = now.Add(300 * time.Millisecond)
	ethARP2 := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x13},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpPoison := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x13},
		SourceProtAddress: []byte{192, 168, 1, 1},
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    []byte{192, 168, 1, 1},
	}
	writePacket(now, ethARP2, arpPoison)

	// 5. Scenario: Port Scanning & Stealth Flag Probes (Nmap Xmas Scan)
	now = now.Add(400 * time.Millisecond)
	scannerIP := net.IPv4(10, 0, 0, 99)
	targetIP := net.IPv4(192, 168, 1, 50)
	ethScan := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x13},
		DstMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x11, 0x22, 0x33},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipScan := &layers.IPv4{
		Version:  4,
		SrcIP:    scannerIP,
		DstIP:    targetIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      48,
	}

	// Xmas Scan packet: FIN + PSH + URG
	tcpXmas := &layers.TCP{
		SrcPort: 45678,
		DstPort: 80,
		Seq:     1001,
		FIN:     true,
		PSH:     true,
		URG:     true,
		Window:  1024,
	}
	tcpXmas.SetNetworkLayerForChecksum(ipScan)
	writePacket(now, ethScan, ipScan, tcpXmas)

	// Null Scan packet: No flags
	now = now.Add(50 * time.Millisecond)
	tcpNull := &layers.TCP{
		SrcPort: 45679,
		DstPort: 443,
		Seq:     1002,
		Window:  1024,
	}
	tcpNull.SetNetworkLayerForChecksum(ipScan)
	writePacket(now, ethScan, ipScan, tcpNull)

	// Multi-port rapid sweep (ports 20..35)
	for port := uint16(20); port <= 35; port++ {
		now = now.Add(10 * time.Millisecond)
		tcpSweep := &layers.TCP{
			SrcPort: 50000 + layers.TCPPort(port),
			DstPort: layers.TCPPort(port),
			Seq:     uint32(2000 + port),
			SYN:     true,
			Window:  1024, // Masscan characteristic
		}
		tcpSweep.SetNetworkLayerForChecksum(ipScan)
		writePacket(now, ethScan, ipScan, tcpSweep)
	}

	// 6. Scenario: HTTP File Transfer & Executable Payload Carving (beacon.exe)
	now = now.Add(500 * time.Millisecond)
	serverIP := net.IPv4(198, 51, 100, 25)
	clientIP := net.IPv4(192, 168, 1, 100)

	ipHTTP := &layers.IPv4{
		Version:  4,
		SrcIP:    serverIP,
		DstIP:    clientIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      56,
	}

	// Synthesize PE executable payload with MZ header
	exePayload := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00NetForensics Simulated Cobalt Strike Beacon Payload\x00")
	httpResponse := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/vnd.microsoft.portable-executable\r\n"+
		"Content-Disposition: attachment; filename=\"beacon.exe\"\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s", len(exePayload), string(exePayload))

	tcpHTTP := &layers.TCP{
		SrcPort: 80,
		DstPort: 49200,
		Seq:     5001,
		ACK:     true,
		PSH:     true,
		Window:  65535,
	}
	tcpHTTP.SetNetworkLayerForChecksum(ipHTTP)

	writePacket(now, ethScan, ipHTTP, tcpHTTP, gopacket.Payload([]byte(httpResponse)))

	fmt.Printf("[+] Synthetic forensic PCAP generated successfully at: %s\n", outPath)
}
