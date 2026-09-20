// Package reassembly_test contains unit tests for TCP stream reassembly and file carving.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package reassembly_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
	"netforensics/pkg/reassembly"
)

func TestCarverAndHashing(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "carver_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	carver, err := reassembly.NewCarver(tempDir)
	if err != nil {
		t.Fatalf("failed to create carver: %v", err)
	}

	var notified forensics.ArtifactRecord
	carver.SubscribeArtifacts(func(record forensics.ArtifactRecord) {
		notified = record
	})

	// Test payload: simulated PDF document
	pdfPayload := append([]byte("%PDF-1.4\n"), []byte("Forensic evidence report test")...)
	flow := protocols.FlowKey{
		SrcIP:   "192.168.1.50",
		DstIP:   "10.0.0.5",
		SrcPort: 80,
		DstPort: 49152,
		Proto:   "TCP",
	}

	record, err := carver.CarvePayload(pdfPayload, flow, "confidential_document.pdf", time.Now())
	if err != nil {
		t.Fatalf("CarvePayload failed: %v", err)
	}

	if record == nil {
		t.Fatalf("expected non-nil record")
	}
	if record.Filename != "confidential_document.pdf" {
		t.Errorf("expected filename confidential_document.pdf, got %s", record.Filename)
	}
	if record.MIMEType != "application/pdf" {
		t.Errorf("expected MIME type application/pdf, got %s", record.MIMEType)
	}
	if record.SizeBytes != int64(len(pdfPayload)) {
		t.Errorf("expected size %d, got %d", len(pdfPayload), record.SizeBytes)
	}
	if len(record.SHA256) != 64 {
		t.Errorf("invalid SHA-256 length: %s", record.SHA256)
	}
	if len(record.MD5) != 32 {
		t.Errorf("invalid MD5 length: %s", record.MD5)
	}

	// Verify file was written to disk
	savedContent, err := os.ReadFile(record.FilePath)
	if err != nil {
		t.Fatalf("failed to read carved file on disk: %v", err)
	}
	if string(savedContent) != string(pdfPayload) {
		t.Errorf("carved file content mismatch")
	}

	// Verify hook subscription
	if notified.ID != record.ID {
		t.Errorf("notification hook did not receive matching record ID")
	}

	// Verify artifact listing
	artifacts := carver.GetCarvedArtifacts()
	if len(artifacts) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(artifacts))
	}
}

func TestMIMEDetection(t *testing.T) {
	tests := []struct {
		name         string
		payload      []byte
		expectedMIME string
		expectedExt  string
		isThreat     bool
	}{
		{
			name:         "Windows PE EXE",
			payload:      []byte{0x4D, 0x5A, 0x90, 0x00, 0x03},
			expectedMIME: "application/vnd.microsoft.portable-executable",
			expectedExt:  ".exe",
			isThreat:     true,
		},
		{
			name:         "Linux ELF",
			payload:      []byte{0x7F, 0x45, 0x4C, 0x46, 0x02},
			expectedMIME: "application/x-executable",
			expectedExt:  ".elf",
			isThreat:     true,
		},
		{
			name:         "PNG Image",
			payload:      []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expectedMIME: "image/png",
			expectedExt:  ".png",
			isThreat:     false,
		},
		{
			name:         "ZIP Archive",
			payload:      []byte{0x50, 0x4B, 0x03, 0x04, 0x14},
			expectedMIME: "application/zip",
			expectedExt:  ".zip",
			isThreat:     false,
		},
	}

	for _, tt := range tests {
		mimeType, ext, threat := reassembly.DetectMIMEAndExtension(tt.payload)
		if mimeType != tt.expectedMIME {
			t.Errorf("[%s] expected MIME %s, got %s", tt.name, tt.expectedMIME, mimeType)
		}
		if ext != tt.expectedExt {
			t.Errorf("[%s] expected Ext %s, got %s", tt.name, tt.expectedExt, ext)
		}
		if threat != tt.isThreat {
			t.Errorf("[%s] expected Threat %v, got %v", tt.name, tt.isThreat, threat)
		}
	}
}

func TestFTPTracker(t *testing.T) {
	tracker := reassembly.NewFTPTracker()
	now := time.Now()

	ctrlFlow := protocols.FlowKey{
		SrcIP:   "192.168.1.10",
		DstIP:   "192.168.1.200",
		SrcPort: 51234,
		DstPort: 21,
		Proto:   "TCP",
	}

	// 1. Client sends RETR command for an exfiltrated file
	retrCmd := []byte("RETR leaked_database.sql\r\n")
	tracker.InspectFTPControl(ctrlFlow, retrCmd, now)

	// 2. Server replies with PASV port: 192,168,1,200, 195, 80 => port 195*256 + 80 = 50000
	pasvReply := []byte("227 Entering Passive Mode (192,168,1,200,195,80)\r\n")
	serverFlow := protocols.FlowKey{
		SrcIP:   "192.168.1.200",
		DstIP:   "192.168.1.10",
		SrcPort: 21,
		DstPort: 51234,
		Proto:   "TCP",
	}
	tracker.InspectFTPControl(serverFlow, pasvReply, now.Add(time.Millisecond*50))

	// 3. Client establishes data connection to server:50000
	dataFlow := protocols.FlowKey{
		SrcIP:   "192.168.1.10",
		DstIP:   "192.168.1.200",
		SrcPort: 51235,
		DstPort: 50000,
		Proto:   "TCP",
	}

	filename, isFTP := tracker.CorrelateDataTransfer(dataFlow)
	if !isFTP {
		t.Fatalf("expected FTP data transfer correlation to succeed")
	}
	if filename != "leaked_database.sql" {
		t.Errorf("expected filename 'leaked_database.sql', got: %s", filename)
	}
}

func TestStreamManagerDirectCarve(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "sm_direct_carve_test")
	defer os.RemoveAll(tempDir)

	carver, err := reassembly.NewCarver(tempDir)
	if err != nil {
		t.Fatalf("NewCarver failed: %v", err)
	}

	sm := reassembly.NewStreamManager(carver)
	defer sm.Close()

	flow := protocols.FlowKey{
		SrcIP:   "10.10.10.10",
		DstIP:   "10.10.10.20",
		SrcPort: 8080,
		DstPort: 33333,
		Proto:   "TCP",
	}

	testPayload := []byte("Direct carved network artifact stream content")
	record, err := sm.DirectCarve(testPayload, flow, "stream_test.txt", time.Now())
	if err != nil {
		t.Fatalf("DirectCarve failed: %v", err)
	}

	if record == nil {
		t.Fatalf("expected non-nil artifact record")
	}
	if record.SizeBytes != int64(len(testPayload)) {
		t.Errorf("size mismatch: expected %d, got %d", len(testPayload), record.SizeBytes)
	}
}
