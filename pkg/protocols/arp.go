// Package protocols contains protocol decoders for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package protocols

import (
	"bytes"
	"net"

	"github.com/google/gopacket/layers"
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ParseARP extracts structured ARP data from a layers.ARP pointer.
func ParseARP(arp *layers.ARP) *ARPEvent {
	if arp == nil {
		return nil
	}

	opStr := "Request"
	if arp.Operation == layers.ARPReply {
		opStr = "Reply"
	}

	senderIP := net.IP(arp.SourceProtAddress)
	targetIP := net.IP(arp.DstProtAddress)
	senderMAC := net.HardwareAddr(arp.SourceHwAddress)
	targetMAC := net.HardwareAddr(arp.DstHwAddress)

	// A gratuitous ARP is typically characterized by:
	// 1. Sender IP equals Target IP in an announcement
	// 2. An ARP reply sent to the broadcast MAC
	isGratuitous := false
	if senderIP.Equal(targetIP) {
		isGratuitous = true
	} else if arp.Operation == layers.ARPReply && bytes.Equal(targetMAC, broadcastMAC) {
		isGratuitous = true
	}

	return &ARPEvent{
		Operation:    opStr,
		SenderIP:     senderIP,
		SenderMAC:    senderMAC,
		TargetIP:     targetIP,
		TargetMAC:    targetMAC,
		IsGratuitous: isGratuitous,
	}
}
