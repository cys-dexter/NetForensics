// Package reassembly provides TCP stream reassembly and automated forensic file carving.
// Author: Ahmad (https://github.com/cys-dexter)
package reassembly

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
)

// FileSignature describes file header magic bytes and metadata.
type FileSignature struct {
	Magic     []byte
	Offset    int
	MIMEType  string
	Extension string
	IsThreat  bool
}

var knownSignatures = []FileSignature{
	// PE Executable (Windows EXE / DLL)
	{Magic: []byte{0x4D, 0x5A}, Offset: 0, MIMEType: "application/vnd.microsoft.portable-executable", Extension: ".exe", IsThreat: true},
	// ELF Executable (Linux binary)
	{Magic: []byte{0x7F, 0x45, 0x4C, 0x46}, Offset: 0, MIMEType: "application/x-executable", Extension: ".elf", IsThreat: true},
	// PDF Document
	{Magic: []byte("%PDF-"), Offset: 0, MIMEType: "application/pdf", Extension: ".pdf", IsThreat: false},
	// ZIP Archive / Office Open XML (DOCX, XLSX)
	{Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Offset: 0, MIMEType: "application/zip", Extension: ".zip", IsThreat: false},
	// PNG Image
	{Magic: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, Offset: 0, MIMEType: "image/png", Extension: ".png", IsThreat: false},
	// JPEG Image
	{Magic: []byte{0xFF, 0xD8, 0xFF}, Offset: 0, MIMEType: "image/jpeg", Extension: ".jpg", IsThreat: false},
	// GIF Image
	{Magic: []byte("GIF87a"), Offset: 0, MIMEType: "image/gif", Extension: ".gif", IsThreat: false},
	{Magic: []byte("GIF89a"), Offset: 0, MIMEType: "image/gif", Extension: ".gif", IsThreat: false},
	// GZIP Archive
	{Magic: []byte{0x1F, 0x8B}, Offset: 0, MIMEType: "application/gzip", Extension: ".gz", IsThreat: false},
	// 7-Zip Archive
	{Magic: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Offset: 0, MIMEType: "application/x-7z-compressed", Extension: ".7z", IsThreat: false},
	// Shell Script
	{Magic: []byte("#!/bin/"), Offset: 0, MIMEType: "text/x-shellscript", Extension: ".sh", IsThreat: true},
}

// Carver manages the extraction, hashing, and cataloging of forensic artifacts.
type Carver struct {
	mu           sync.RWMutex
	artifactsDir string
	artifacts    []forensics.ArtifactRecord
	hooks        []func(forensics.ArtifactRecord)
}

// NewCarver creates a file carving manager saving artifacts into the target directory.
func NewCarver(artifactsDir string) (*Carver, error) {
	if artifactsDir == "" {
		artifactsDir = "./extracted_artifacts"
	}

	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to initialize artifact directory %s: %w", artifactsDir, err)
	}

	return &Carver{
		artifactsDir: artifactsDir,
		artifacts:    make([]forensics.ArtifactRecord, 0),
		hooks:        make([]func(forensics.ArtifactRecord), 0),
	}, nil
}

// SubscribeArtifacts registers a callback triggered whenever a new file is carved.
func (c *Carver) SubscribeArtifacts(hook func(forensics.ArtifactRecord)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hooks = append(c.hooks, hook)
}

// DetectMIMEAndExtension performs magic-byte and content inspection to identify file type.
func DetectMIMEAndExtension(payload []byte) (mimeType, ext string, isThreat bool) {
	if len(payload) == 0 {
		return "application/octet-stream", ".bin", false
	}

	// Match signature table first
	for _, sig := range knownSignatures {
		if len(payload) >= sig.Offset+len(sig.Magic) {
			if bytes.Equal(payload[sig.Offset:sig.Offset+len(sig.Magic)], sig.Magic) {
				return sig.MIMEType, sig.Extension, sig.IsThreat
			}
		}
	}

	// Standard Go content-type sniffer fallback
	detected := http.DetectContentType(payload)
	switch {
	case strings.HasPrefix(detected, "text/html"):
		return detected, ".html", false
	case strings.HasPrefix(detected, "text/plain"):
		// Check for script or suspicious strings
		if bytes.Contains(payload, []byte("eval(")) || bytes.Contains(payload, []byte("<script")) {
			return detected, ".txt", true
		}
		return detected, ".txt", false
	case strings.HasPrefix(detected, "application/json"):
		return detected, ".json", false
	case strings.HasPrefix(detected, "application/xml"):
		return detected, ".xml", false
	}

	return detected, ".bin", false
}

// CarvePayload writes an extracted byte payload to disk, hashes it, and registers an ArtifactRecord.
func (c *Carver) CarvePayload(payload []byte, flow protocols.FlowKey, suggestedName string, timestamp time.Time) (*forensics.ArtifactRecord, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	mimeType, ext, isThreatSig := DetectMIMEAndExtension(payload)

	// Clean suggested name
	filename := sanitizeFilename(suggestedName)
	if filename == "" {
		filename = fmt.Sprintf("artifact_%s_%d%s", flow.DstIP, timestamp.Unix(), ext)
	} else if filepath.Ext(filename) == "" {
		filename += ext
	}

	// Calculate SHA-256 and MD5 hashes
	hashes := forensics.ComputeHashes(payload)

	// Determine threat level indicator
	threatIndicator := forensics.LevelSafe
	if isThreatSig {
		threatIndicator = forensics.LevelThreat
	} else if strings.HasPrefix(mimeType, "application/") && !strings.Contains(mimeType, "json") && !strings.Contains(mimeType, "xml") {
		threatIndicator = forensics.LevelWarning
	}

	// Write file to extracted_artifacts/ directory
	c.mu.Lock()
	destPath := filepath.Join(c.artifactsDir, filename)

	// Deduplicate if file already exists with same name
	if _, err := os.Stat(destPath); err == nil {
		destPath = filepath.Join(c.artifactsDir, fmt.Sprintf("%s_%s%s", strings.TrimSuffix(filename, filepath.Ext(filename)), hashes.SHA256[:8], filepath.Ext(filename)))
		filename = filepath.Base(destPath)
	}

	if err := os.WriteFile(destPath, payload, 0644); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("failed writing carved file %s: %w", destPath, err)
	}

	record := forensics.ArtifactRecord{
		ID:              fmt.Sprintf("ART-%s-%d", hashes.SHA256[:8], timestamp.UnixNano()),
		Filename:        filename,
		FilePath:        destPath,
		SizeBytes:       int64(len(payload)),
		MIMEType:        mimeType,
		SHA256:          hashes.SHA256,
		MD5:             hashes.MD5,
		SourceIP:        flow.SrcIP,
		DestIP:          flow.DstIP,
		SourcePort:      flow.SrcPort,
		DestPort:        flow.DstPort,
		Protocol:        flow.Proto,
		Timestamp:       timestamp,
		ThreatIndicator: threatIndicator,
	}

	c.artifacts = append(c.artifacts, record)
	hooks := append([]func(forensics.ArtifactRecord){}, c.hooks...)
	c.mu.Unlock()

	for _, h := range hooks {
		h(record)
	}

	return &record, nil
}

// GetCarvedArtifacts returns an immutable copy of all carved artifacts.
func (c *Carver) GetCarvedArtifacts() []forensics.ArtifactRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]forensics.ArtifactRecord, len(c.artifacts))
	copy(out, c.artifacts)
	return out
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "..", "")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.TrimSpace(name)
	if name == "." || name == "/" || name == "\\" {
		return ""
	}
	return name
}
