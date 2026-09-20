// Package capture provides live and offline network packet ingestion capabilities.
// Author: Ahmad (https://github.com/cys-dexter)
package capture

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// EngineConfig holds configuration parameters for the packet capture engine.
type EngineConfig struct {
	Interface    string        // Network interface name for live capture
	PCAPFile     string        // Path to PCAP or PCAPNG file for offline analysis
	BPFFilter    string        // Berkeley Packet Filter string (e.g. "tcp and port 80")
	Promiscuous  bool          // Promiscuous mode for live interface
	SnapLen      int32         // Snapshot length in bytes (default: 65535)
	ReadTimeout  time.Duration // Read timeout for live capture buffer
	PacketBuffer int           // Channel buffer size
}

// DefaultConfig returns production-ready default engine parameters.
func DefaultConfig() EngineConfig {
	return EngineConfig{
		Interface:    "",
		PCAPFile:     "",
		BPFFilter:    "",
		Promiscuous:  true,
		SnapLen:      65535,
		ReadTimeout:  time.Millisecond * 100,
		PacketBuffer: 4096,
	}
}

// Engine defines the contract for network packet capture operations.
type Engine struct {
	cfg        EngineConfig
	stats      *PacketStats
	packetChan chan gopacket.Packet
	errChan    chan error
	handle     *pcap.Handle
	fileHandle *os.File
	isLive     bool
}

// NewEngine creates and initializes a capture engine based on configuration.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65535
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = time.Millisecond * 100
	}
	if cfg.PacketBuffer <= 0 {
		cfg.PacketBuffer = 4096
	}

	return &Engine{
		cfg:        cfg,
		stats:      NewPacketStats(),
		packetChan: make(chan gopacket.Packet, cfg.PacketBuffer),
		errChan:    make(chan error, 10),
		isLive:     cfg.PCAPFile == "",
	}
}

// Packets returns the read-only channel through which ingested packets are streamed.
func (e *Engine) Packets() <-chan gopacket.Packet {
	return e.packetChan
}

// Errors returns the error notification channel.
func (e *Engine) Errors() <-chan error {
	return e.errChan
}

// Stats returns the statistics tracker.
func (e *Engine) Stats() *PacketStats {
	return e.stats
}

// IsLive returns true if capturing from a live interface, or false for offline files.
func (e *Engine) IsLive() bool {
	return e.isLive
}

// Start launches the ingestion pipeline. It runs asynchronously until context cancellation or EOF.
func (e *Engine) Start(ctx context.Context) error {
	var packetSource *gopacket.PacketSource

	if e.isLive {
		if e.cfg.Interface == "" {
			return fmt.Errorf("live capture requires a valid network interface")
		}
		handle, err := pcap.OpenLive(e.cfg.Interface, e.cfg.SnapLen, e.cfg.Promiscuous, e.cfg.ReadTimeout)
		if err != nil {
			return fmt.Errorf("failed to open live interface %s: %w", e.cfg.Interface, err)
		}
		e.handle = handle

		if e.cfg.BPFFilter != "" {
			if err := e.handle.SetBPFFilter(e.cfg.BPFFilter); err != nil {
				e.handle.Close()
				return fmt.Errorf("invalid BPF filter %q: %w", e.cfg.BPFFilter, err)
			}
		}
		packetSource = gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	} else {
		// Offline PCAP/PCAPNG inspection
		if _, err := os.Stat(e.cfg.PCAPFile); err != nil {
			return fmt.Errorf("PCAP file does not exist: %w", err)
		}

		// Try libpcap offline reader first
		handle, err := pcap.OpenOffline(e.cfg.PCAPFile)
		if err == nil {
			e.handle = handle
			if e.cfg.BPFFilter != "" {
				if err := e.handle.SetBPFFilter(e.cfg.BPFFilter); err != nil {
					e.handle.Close()
					return fmt.Errorf("invalid BPF filter %q: %w", e.cfg.BPFFilter, err)
				}
			}
			packetSource = gopacket.NewPacketSource(e.handle, e.handle.LinkType())
		} else {
			// Fallback to pure-Go pcapgo reader (supports PCAP and PCAPNG without CGO)
			file, fErr := os.Open(e.cfg.PCAPFile)
			if fErr != nil {
				return fmt.Errorf("failed to open offline file %s: %w", e.cfg.PCAPFile, fErr)
			}
			e.fileHandle = file

			// Try pcapng reader first
			ngReader, ngErr := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
			if ngErr == nil {
				packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
			} else {
				// Rewind and try legacy pcap reader
				file.Seek(0, 0)
				legacyReader, lErr := pcapgo.NewReader(file)
				if lErr != nil {
					file.Close()
					return fmt.Errorf("unsupported PCAP format for %s: %v (libpcap err: %v)", e.cfg.PCAPFile, lErr, err)
				}
				packetSource = gopacket.NewPacketSource(legacyReader, legacyReader.LinkType())
			}
		}
	}

	go e.runWorker(ctx, packetSource)
	return nil
}

// runWorker processes packets from the packet source and distributes them to consumers.
func (e *Engine) runWorker(ctx context.Context, source *gopacket.PacketSource) {
	defer close(e.packetChan)
	defer e.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := source.NextPacket()
			if err != nil {
				// For offline files, io.EOF or similar signals end of capture
				if !e.isLive {
					return
				}
				// For live captures, record transient read error if any
				select {
				case e.errChan <- err:
				default:
				}
				continue
			}

			if packet == nil {
				continue
			}

			// Record statistical breakdown
			e.inspectPacketStats(packet)

			// Deliver packet to consumer channel safely
			select {
			case e.packetChan <- packet:
			case <-ctx.Done():
				return
			}
		}
	}
}

// inspectPacketStats updates the real-time counters based on packet layers.
func (e *Engine) inspectPacketStats(packet gopacket.Packet) {
	length := uint64(len(packet.Data()))

	isIPv4 := packet.Layer(layers.LayerTypeIPv4) != nil
	isIPv6 := packet.Layer(layers.LayerTypeIPv6) != nil
	isTCP := packet.Layer(layers.LayerTypeTCP) != nil
	isUDP := packet.Layer(layers.LayerTypeUDP) != nil
	isICMP := packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil
	isARP := packet.Layer(layers.LayerTypeARP) != nil

	// Check higher level heuristics
	isDNS := packet.Layer(layers.LayerTypeDNS) != nil
	if !isDNS && isUDP {
		if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			if udp.SrcPort == 53 || udp.DstPort == 53 {
				isDNS = true
			}
		}
	}

	isHTTP := false
	isTLS := false
	if isTCP {
		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			if tcp.SrcPort == 80 || tcp.DstPort == 80 || tcp.SrcPort == 8080 || tcp.DstPort == 8080 {
				isHTTP = true
			}
			if tcp.SrcPort == 443 || tcp.DstPort == 443 || tcp.SrcPort == 8443 || tcp.DstPort == 8443 {
				isTLS = true
			}
		}
	}

	e.stats.IncrPacket(length, isIPv4, isIPv6, isTCP, isUDP, isICMP, isARP, isDNS, isHTTP, isTLS)
}

// Close gracefully releases any libpcap handles or file descriptors.
func (e *Engine) Close() {
	if e.handle != nil {
		e.handle.Close()
		e.handle = nil
	}
	if e.fileHandle != nil {
		e.fileHandle.Close()
		e.fileHandle = nil
	}
}
