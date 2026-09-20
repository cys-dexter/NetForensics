// Package reassembly provides FTP command tracking and data channel file carving.
// Author: Ahmad (https://github.com/cys-dexter)
package reassembly

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netforensics/pkg/protocols"
)

var (
	pasvRegex = regexp.MustCompile(`227 Entering Passive Mode \((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)
	portRegex = regexp.MustCompile(`PORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)`)
	retrRegex = regexp.MustCompile(`(?i)^RETR\s+(.+)`)
	storRegex = regexp.MustCompile(`(?i)^STOR\s+(.+)`)
)

func ftpSessionKey(ip1, ip2 string) string {
	if ip1 < ip2 {
		return ip1 + "<->" + ip2
	}
	return ip2 + "<->" + ip1
}

// FTPPendingTransfer associates expected data flows with the requested file name.
type FTPPendingTransfer struct {
	ClientIP  string
	ServerIP  string
	DataPort  uint16
	Filename  string
	IsUpload  bool
	Timestamp time.Time
}

// FTPTracker monitors FTP control channels (port 21) to correlate data channel file transfers.
type FTPTracker struct {
	mu        sync.Mutex
	transfers map[string]*FTPPendingTransfer // Key: IP:Port of expected data channel
	lastFiles map[string]string              // Key: sessionKey -> last RETR/STOR filename
}

// NewFTPTracker initializes a tracker for FTP command sessions.
func NewFTPTracker() *FTPTracker {
	return &FTPTracker{
		transfers: make(map[string]*FTPPendingTransfer),
		lastFiles: make(map[string]string),
	}
}

// InspectFTPControl parses FTP command and response strings on port 21.
func (t *FTPTracker) InspectFTPControl(flow protocols.FlowKey, payload []byte, timestamp time.Time) {
	if flow.SrcPort != 21 && flow.DstPort != 21 {
		return
	}

	text := string(payload)
	lines := strings.Split(text, "\r\n")

	t.mu.Lock()
	defer t.mu.Unlock()

	sKey := ftpSessionKey(flow.SrcIP, flow.DstIP)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Client commands: RETR / STOR
		if retrMatch := retrRegex.FindStringSubmatch(line); len(retrMatch) > 1 {
			filename := strings.TrimSpace(retrMatch[1])
			t.lastFiles[sKey] = filename
		} else if storMatch := storRegex.FindStringSubmatch(line); len(storMatch) > 1 {
			filename := strings.TrimSpace(storMatch[1])
			t.lastFiles[sKey] = filename
		}

		// Server PASV response
		if pasvMatch := pasvRegex.FindStringSubmatch(line); len(pasvMatch) == 7 {
			p1, _ := strconv.Atoi(pasvMatch[5])
			p2, _ := strconv.Atoi(pasvMatch[6])
			dataPort := uint16(p1*256 + p2)
			serverIP := fmt.Sprintf("%s.%s.%s.%s", pasvMatch[1], pasvMatch[2], pasvMatch[3], pasvMatch[4])

			dataKey := fmt.Sprintf("%s:%d", serverIP, dataPort)
			t.transfers[dataKey] = &FTPPendingTransfer{
				ClientIP:  flow.DstIP,
				ServerIP:  serverIP,
				DataPort:  dataPort,
				Filename:  t.lastFiles[sKey],
				Timestamp: timestamp,
			}
		}

		// Client PORT command
		if portMatch := portRegex.FindStringSubmatch(line); len(portMatch) == 7 {
			p1, _ := strconv.Atoi(portMatch[5])
			p2, _ := strconv.Atoi(portMatch[6])
			dataPort := uint16(p1*256 + p2)
			clientIP := fmt.Sprintf("%s.%s.%s.%s", portMatch[1], portMatch[2], portMatch[3], portMatch[4])

			dataKey := fmt.Sprintf("%s:%d", clientIP, dataPort)
			t.transfers[dataKey] = &FTPPendingTransfer{
				ClientIP:  clientIP,
				ServerIP:  flow.DstIP,
				DataPort:  dataPort,
				Filename:  t.lastFiles[sKey],
				Timestamp: timestamp,
			}
		}
	}
}

// CorrelateDataTransfer checks if a data connection corresponds to an expected FTP file transfer.
func (t *FTPTracker) CorrelateDataTransfer(flow protocols.FlowKey) (filename string, isFTP bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Direct check for standard FTP-DATA port 20
	if flow.SrcPort == 20 || flow.DstPort == 20 {
		sKey := ftpSessionKey(flow.SrcIP, flow.DstIP)
		if fn, exists := t.lastFiles[sKey]; exists && fn != "" {
			return fn, true
		}
		return fmt.Sprintf("ftp_data_%s_%d.bin", flow.DstIP, flow.DstPort), true
	}

	// Check dynamic ports registered via PASV or PORT
	k1 := fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort)
	k2 := fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort)

	if transfer, exists := t.transfers[k1]; exists {
		delete(t.transfers, k1)
		fn := transfer.Filename
		if fn == "" {
			fn = fmt.Sprintf("ftp_data_%d.bin", flow.SrcPort)
		}
		return fn, true
	}

	if transfer, exists := t.transfers[k2]; exists {
		delete(t.transfers, k2)
		fn := transfer.Filename
		if fn == "" {
			fn = fmt.Sprintf("ftp_data_%d.bin", flow.DstPort)
		}
		return fn, true
	}

	return "", false
}
