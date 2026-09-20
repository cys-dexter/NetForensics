// Package capture provides packet capture, ingestion, and metric tracking engines.
// Author: Ahmad (https://github.com/cys-dexter)
package capture

import (
	"sync"
	"time"
)

// PacketStats tracks comprehensive real-time network traffic counters.
type PacketStats struct {
	mu sync.RWMutex

	StartTime      time.Time
	LastPacketTime time.Time

	TotalPackets uint64
	TotalBytes   uint64

	IPv4Packets uint64
	IPv6Packets uint64
	TCPPackets  uint64
	UDPPackets  uint64
	ICMPPackets uint64
	ARPPackets  uint64
	DNSPackets  uint64
	HTTPPackets uint64
	TLSPackets  uint64
	OtherPackets uint64

	DroppedPackets uint64

	// Rate calculation helpers
	lastSampleTime   time.Time
	lastSampleBytes  uint64
	lastSamplePackets uint64
	currentPPS       float64
	currentBPS       float64
}

// StatsSnapshot is an immutable copy of the stats at a single point in time.
type StatsSnapshot struct {
	StartTime      time.Time     `json:"start_time"`
	Duration       time.Duration `json:"duration"`
	TotalPackets   uint64        `json:"total_packets"`
	TotalBytes     uint64        `json:"total_bytes"`
	IPv4Packets    uint64        `json:"ipv4_packets"`
	IPv6Packets    uint64        `json:"ipv6_packets"`
	TCPPackets     uint64        `json:"tcp_packets"`
	UDPPackets     uint64        `json:"udp_packets"`
	ICMPPackets    uint64        `json:"icmp_packets"`
	ARPPackets     uint64        `json:"arp_packets"`
	DNSPackets     uint64        `json:"dns_packets"`
	HTTPPackets    uint64        `json:"http_packets"`
	TLSPackets     uint64        `json:"tls_packets"`
	OtherPackets   uint64        `json:"other_packets"`
	DroppedPackets uint64        `json:"dropped_packets"`
	PacketsPerSec  float64       `json:"packets_per_sec"`
	BytesPerSec    float64       `json:"bytes_per_sec"`
}

// NewPacketStats initializes a new statistics container.
func NewPacketStats() *PacketStats {
	now := time.Now()
	return &PacketStats{
		StartTime:      now,
		LastPacketTime: now,
		lastSampleTime: now,
	}
}

// IncrPacket updates stats counters for an ingested packet.
func (s *PacketStats) IncrPacket(bytes uint64, isIPv4, isIPv6, isTCP, isUDP, isICMP, isARP, isDNS, isHTTP, isTLS bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.LastPacketTime = now
	s.TotalPackets++
	s.TotalBytes += bytes

	if isIPv4 {
		s.IPv4Packets++
	} else if isIPv6 {
		s.IPv6Packets++
	}

	if isTCP {
		s.TCPPackets++
	}
	if isUDP {
		s.UDPPackets++
	}
	if isICMP {
		s.ICMPPackets++
	}
	if isARP {
		s.ARPPackets++
	}
	if isDNS {
		s.DNSPackets++
	}
	if isHTTP {
		s.HTTPPackets++
	}
	if isTLS {
		s.TLSPackets++
	}
	if !isTCP && !isUDP && !isICMP && !isARP {
		s.OtherPackets++
	}

	// Update rate if 1 second has elapsed
	sampleElapsed := now.Sub(s.lastSampleTime).Seconds()
	if sampleElapsed >= 1.0 {
		pktDiff := s.TotalPackets - s.lastSamplePackets
		byteDiff := s.TotalBytes - s.lastSampleBytes
		s.currentPPS = float64(pktDiff) / sampleElapsed
		s.currentBPS = float64(byteDiff) / sampleElapsed

		s.lastSampleTime = now
		s.lastSamplePackets = s.TotalPackets
		s.lastSampleBytes = s.TotalBytes
	}
}

// Snapshot returns an atomic read of the current metric snapshot.
func (s *PacketStats) Snapshot() StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	duration := now.Sub(s.StartTime)
	if s.TotalPackets > 0 && !s.LastPacketTime.IsZero() {
		duration = s.LastPacketTime.Sub(s.StartTime)
	}
	if duration <= 0 {
		duration = time.Millisecond
	}

	return StatsSnapshot{
		StartTime:      s.StartTime,
		Duration:       duration,
		TotalPackets:   s.TotalPackets,
		TotalBytes:     s.TotalBytes,
		IPv4Packets:    s.IPv4Packets,
		IPv6Packets:    s.IPv6Packets,
		TCPPackets:     s.TCPPackets,
		UDPPackets:     s.UDPPackets,
		ICMPPackets:    s.ICMPPackets,
		ARPPackets:     s.ARPPackets,
		DNSPackets:     s.DNSPackets,
		HTTPPackets:    s.HTTPPackets,
		TLSPackets:     s.TLSPackets,
		OtherPackets:   s.OtherPackets,
		DroppedPackets: s.DroppedPackets,
		PacketsPerSec:  s.currentPPS,
		BytesPerSec:    s.currentBPS,
	}
}
