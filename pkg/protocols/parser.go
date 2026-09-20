// Package protocols provides protocol dissectors and metadata extractors for DFIR analysis.
// Author: Ahmad (https://github.com/cys-dexter)
package protocols

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowKey represents a bidirectional or unidirectional network flow.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

func (f FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d [%s]", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto)
}

// FlowKeySymmetric returns an order-independent string identifier for a connection.
func (f FlowKey) FlowKeySymmetric() string {
	ep1 := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
	ep2 := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
	if ep1 < ep2 {
		return fmt.Sprintf("%s <-> %s [%s]", ep1, ep2, f.Proto)
	}
	return fmt.Sprintf("%s <-> %s [%s]", ep2, ep1, f.Proto)
}

// NetworkEvent wraps essential protocol dissection data for forensic correlation.
type NetworkEvent struct {
	Timestamp  time.Time
	Flow       FlowKey
	SrcMAC     net.HardwareAddr
	DstMAC     net.HardwareAddr
	Length     int
	HTTPEvent  *HTTPEvent
	DNSEvent   *DNSEvent
	ARPEvent   *ARPEvent
	TLSSNI     string
	TCPFlags   TCPFlagInfo
}

// TCPFlagInfo details TCP control flags.
type TCPFlagInfo struct {
	IsTCP bool
	SYN   bool
	ACK   bool
	FIN   bool
	RST   bool
	PSH   bool
	URG   bool
	ECE   bool
	CWR   bool
	NS    bool
	Window uint16
	Seq   uint32
	Ack   uint32
}

// ParsePacket inspects a raw packet and extracts protocol forensic artifacts.
func ParsePacket(packet gopacket.Packet) *NetworkEvent {
	if packet == nil {
		return nil
	}

	ev := &NetworkEvent{
		Timestamp: packet.Metadata().Timestamp,
		Length:    len(packet.Data()),
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	// Link Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			ev.SrcMAC = eth.SrcMAC
			ev.DstMAC = eth.DstMAC
		}
	}

	// Network Layer
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			ev.Flow.SrcIP = ip4.SrcIP.String()
			ev.Flow.DstIP = ip4.DstIP.String()
			ev.Flow.Proto = ip4.Protocol.String()
		}
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			ev.Flow.SrcIP = ip6.SrcIP.String()
			ev.Flow.DstIP = ip6.DstIP.String()
			ev.Flow.Proto = ip6.NextHeader.String()
		}
	}

	// Transport Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			ev.Flow.SrcPort = uint16(tcp.SrcPort)
			ev.Flow.DstPort = uint16(tcp.DstPort)
			ev.Flow.Proto = "TCP"

			ev.TCPFlags = TCPFlagInfo{
				IsTCP:  true,
				SYN:    tcp.SYN,
				ACK:    tcp.ACK,
				FIN:    tcp.FIN,
				RST:    tcp.RST,
				PSH:    tcp.PSH,
				URG:    tcp.URG,
				ECE:    tcp.ECE,
				CWR:    tcp.CWR,
				NS:     tcp.NS,
				Window: tcp.Window,
				Seq:    tcp.Seq,
				Ack:    tcp.Ack,
			}

			// Check for HTTP payload in raw TCP
			if len(tcp.Payload) > 0 {
				if httpEv := ParseHTTPPayload(tcp.Payload, ev.Flow.SrcPort, ev.Flow.DstPort); httpEv != nil {
					ev.HTTPEvent = httpEv
				}
				// Check for TLS Client Hello SNI
				if sni := ExtractTLSSNI(tcp.Payload); sni != "" {
					ev.TLSSNI = sni
				}
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			ev.Flow.SrcPort = uint16(udp.SrcPort)
			ev.Flow.DstPort = uint16(udp.DstPort)
			ev.Flow.Proto = "UDP"
		}
	}

	// Application Layer - DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if dns, ok := dnsLayer.(*layers.DNS); ok {
			ev.DNSEvent = ParseDNS(dns)
		}
	} else if ev.Flow.SrcPort == 53 || ev.Flow.DstPort == 53 {
		// Fallback: Parse DNS from UDP payload
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok && len(udp.Payload) > 0 {
				var dns layers.DNS
				if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err == nil {
					ev.DNSEvent = ParseDNS(&dns)
				}
			}
		}
	}

	// ARP Layer
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arp, ok := arpLayer.(*layers.ARP); ok {
			ev.ARPEvent = ParseARP(arp)
		}
	}

	return ev
}

// ExtractTLSSNI extracts the Server Name Indication (SNI) string from a TLS Client Hello packet.
func ExtractTLSSNI(payload []byte) string {
	// TLS Record layer: 0x16 = Handshake, version [0x03, 0x01..0x03]
	if len(payload) < 43 || payload[0] != 0x16 {
		return ""
	}
	// Handshake type 0x01 = Client Hello
	if payload[5] != 0x01 {
		return ""
	}

	offset := 43 // Skip Record Header (5), Handshake Header (4), ClientVersion (2), Random (32)
	if offset >= len(payload) {
		return ""
	}

	// Session ID length
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 >= len(payload) {
		return ""
	}

	// Cipher Suites length
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherSuitesLen
	if offset+1 >= len(payload) {
		return ""
	}

	// Compression Methods length
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 >= len(payload) {
		return ""
	}

	// Extensions length
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	endOffset := offset + extensionsLen
	if endOffset > len(payload) {
		endOffset = len(payload)
	}

	for offset+4 <= endOffset {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4

		if extType == 0 { // Server Name Indication
			if offset+extLen <= endOffset && extLen > 5 {
				// Server Name List Length (2), Server Name Type (1, 0=hostname), Name Length (2)
				nameLen := int(payload[offset+3])<<8 | int(payload[offset+4])
				if offset+5+nameLen <= endOffset {
					return string(payload[offset+5 : offset+5+nameLen])
				}
			}
		}
		offset += extLen
	}
	return ""
}
