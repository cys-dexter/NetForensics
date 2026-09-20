// Package reassembly implements high-throughput TCP stream reassembly and protocol carving.
// Author: Ahmad (https://github.com/cys-dexter)
package reassembly

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
)

// StreamManager coordinates stream factories, the gopacket assembler, and file carving.
type StreamManager struct {
	flowsMu     sync.RWMutex
	asmMu       sync.Mutex
	carver      *Carver
	ftpTracker  *FTPTracker
	pool        *tcpassembly.StreamPool
	assembler   *tcpassembly.Assembler
	activeFlows map[string]*TCPReassemblyStream
	stopChan    chan struct{}
}

// TCPReassemblyStream handles the byte stream for an individual TCP conversation half.
type TCPReassemblyStream struct {
	netFlow   gopacket.Flow
	tcpFlow   gopacket.Flow
	flowKey   protocols.FlowKey
	reader    tcpreader.ReaderStream
	carver    *Carver
	ftp       *FTPTracker
	manager   *StreamManager
	startTime time.Time
}

type streamFactory struct {
	manager *StreamManager
	carver  *Carver
	ftp     *FTPTracker
}

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	srcPort, _ := strconv.ParseUint(tcpFlow.Src().String(), 10, 16)
	dstPort, _ := strconv.ParseUint(tcpFlow.Dst().String(), 10, 16)

	flowKey := protocols.FlowKey{
		SrcIP:   netFlow.Src().String(),
		DstIP:   netFlow.Dst().String(),
		SrcPort: uint16(srcPort),
		DstPort: uint16(dstPort),
		Proto:   "TCP",
	}

	stream := &TCPReassemblyStream{
		netFlow:   netFlow,
		tcpFlow:   tcpFlow,
		flowKey:   flowKey,
		reader:    tcpreader.NewReaderStream(),
		carver:    f.carver,
		ftp:       f.ftp,
		manager:   f.manager,
		startTime: time.Now(),
	}

	f.manager.registerStream(flowKey.String(), stream)
	go stream.run()
	return &stream.reader
}

// NewStreamManager creates a stream reassembly pipeline.
func NewStreamManager(carver *Carver) *StreamManager {
	ftpTracker := NewFTPTracker()
	sm := &StreamManager{
		carver:      carver,
		ftpTracker:  ftpTracker,
		activeFlows: make(map[string]*TCPReassemblyStream),
		stopChan:    make(chan struct{}),
	}

	factory := &streamFactory{manager: sm, carver: carver, ftp: ftpTracker}
	sm.pool = tcpassembly.NewStreamPool(factory)
	sm.assembler = tcpassembly.NewAssembler(sm.pool)

	// Launch periodic stream flush routine
	go sm.periodicFlush()

	return sm
}

func (sm *StreamManager) registerStream(key string, s *TCPReassemblyStream) {
	sm.flowsMu.Lock()
	defer sm.flowsMu.Unlock()
	sm.activeFlows[key] = s
}

func (sm *StreamManager) unregisterStream(key string) {
	sm.flowsMu.Lock()
	defer sm.flowsMu.Unlock()
	delete(sm.activeFlows, key)
}

func (sm *StreamManager) periodicFlush() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopChan:
			return
		case now := <-ticker.C:
			sm.asmMu.Lock()
			sm.assembler.FlushOlderThan(now.Add(-2 * time.Minute))
			sm.asmMu.Unlock()
		}
	}
}

// IngestPacket feeds a packet with a TCP layer into the reassembly assembler.
func (sm *StreamManager) IngestPacket(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Track FTP control packets if port 21
	if (tcp.SrcPort == 21 || tcp.DstPort == 21) && len(tcp.Payload) > 0 {
		flowKey := protocols.FlowKey{
			SrcIP:   netLayer.NetworkFlow().Src().String(),
			DstIP:   netLayer.NetworkFlow().Dst().String(),
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Proto:   "TCP",
		}
		sm.ftpTracker.InspectFTPControl(flowKey, tcp.Payload, packet.Metadata().Timestamp)
	}

	sm.asmMu.Lock()
	sm.assembler.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, packet.Metadata().Timestamp)
	sm.asmMu.Unlock()
}

// FlushComplete forces remaining buffered segments through the reassembly processor.
func (sm *StreamManager) FlushComplete() {
	sm.asmMu.Lock()
	sm.assembler.FlushAll()
	sm.asmMu.Unlock()
}

// Close terminates stream management.
func (sm *StreamManager) Close() {
	select {
	case <-sm.stopChan:
		return
	default:
		close(sm.stopChan)
	}
	sm.FlushComplete()
}

// run consumes reassembled bytes and identifies HTTP payloads or files.
func (s *TCPReassemblyStream) run() {
	defer s.manager.unregisterStream(s.flowKey.String())

	// Read full stream data up to 25MB buffer
	buf := make([]byte, 65536)
	var streamBuffer bytes.Buffer

	for {
		n, err := s.reader.Read(buf)
		if n > 0 {
			streamBuffer.Write(buf[:n])
			if streamBuffer.Len() > 25*1024*1024 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	data := streamBuffer.Bytes()
	if len(data) == 0 {
		return
	}

	// 1. Try decoding as HTTP Request or Response
	httpEv := protocols.ParseHTTPPayload(data, s.flowKey.SrcPort, s.flowKey.DstPort)
	if httpEv != nil && len(httpEv.Body) > 0 {
		filename := httpEv.Filename
		if filename == "" {
			filename = fmt.Sprintf("http_%s_%d", s.flowKey.DstIP, s.startTime.Unix())
		}
		_, _ = s.carver.CarvePayload(httpEv.Body, s.flowKey, filename, s.startTime)
		return
	}

	// 2. Try checking if this was an FTP data transfer
	if s.ftp != nil {
		if ftpFilename, isFTP := s.ftp.CorrelateDataTransfer(s.flowKey); isFTP {
			_, _ = s.carver.CarvePayload(data, s.flowKey, ftpFilename, s.startTime)
			return
		}
	}

	// 3. Direct binary / document signature detection in raw TCP stream
	for _, sig := range knownSignatures {
		idx := bytes.Index(data, sig.Magic)
		if idx != -1 {
			extracted := data[idx:]
			suggestedName := fmt.Sprintf("carved_stream_%s_%d%s", s.flowKey.DstIP, s.startTime.Unix(), sig.Extension)
			_, _ = s.carver.CarvePayload(extracted, s.flowKey, suggestedName, s.startTime)
			return
		}
	}
}

// DirectCarve allows manual or non-assembled payload carving for fast paths.
func (sm *StreamManager) DirectCarve(payload []byte, flow protocols.FlowKey, filename string, timestamp time.Time) (*forensics.ArtifactRecord, error) {
	return sm.carver.CarvePayload(payload, flow, filename, timestamp)
}
