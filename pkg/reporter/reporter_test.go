// Package reporter_test contains unit tests for timeline and reporting engines.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package reporter_test

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
	"netforensics/pkg/reporter"
)

func TestTimelineAndExporters(t *testing.T) {
	tm := reporter.NewTimelineManager()
	now := time.Now()

	// 1. Record a threat alert
	threat := forensics.ThreatAlert{
		ID:         "THREAT-001",
		Timestamp:  now,
		Level:      forensics.LevelThreat,
		Category:   forensics.CategoryDNSTunneling,
		Title:      "DNS Tunneling Detected",
		SourceIP:   "10.0.0.5",
		DestIP:     "8.8.8.8",
		Protocol:   "DNS",
		Details:    "High entropy payload observed in query",
		Evidence:   "Entropy: 4.31 bits/char",
		Confidence: 0.95,
	}
	tm.RecordThreat(threat)

	// 2. Record a carved artifact
	artifact := forensics.ArtifactRecord{
		ID:              "ART-001",
		Filename:        "malware.exe",
		FilePath:        "/tmp/malware.exe",
		SizeBytes:       2048,
		MIMEType:        "application/x-dosexec",
		SHA256:          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		MD5:             "d41d8cd98f00b204e9800998ecf8427e",
		SourceIP:        "10.0.0.5",
		DestIP:          "192.168.1.1",
		SourcePort:      445,
		DestPort:        49152,
		Protocol:        "TCP",
		Timestamp:       now.Add(time.Second),
		ThreatIndicator: forensics.LevelThreat,
	}
	tm.RecordArtifact(artifact)

	// 3. Record a system event
	tm.RecordEvent(reporter.TimelineEvent{
		ID:          "SYS-001",
		Timestamp:   now.Add(2 * time.Second),
		Type:        "SYSTEM",
		Severity:    protocols.SeveritySafe,
		Source:      "localhost",
		Destination: "eth0",
		Protocol:    "SYSTEM",
		Summary:     "Capture Session Completed",
		Details:     "Total packets: 5000",
	})

	// 4. Test Report Generation
	report := tm.GenerateReport()
	if report.TotalEvents != 3 {
		t.Fatalf("expected 3 total events, got %d", report.TotalEvents)
	}
	if report.Investigator != "Ahmad" {
		t.Errorf("expected investigator Ahmad, got %s", report.Investigator)
	}
	if len(report.IntegritySHA256) != 64 {
		t.Errorf("invalid integrity sha256: %s", report.IntegritySHA256)
	}

	// 5. Test JSON Export
	tempDir, err := os.MkdirTemp("", "reporter_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	jsonPath := filepath.Join(tempDir, "timeline.json")
	if err := tm.ExportJSON(jsonPath); err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read exported JSON: %v", err)
	}

	var parsedReport reporter.TimelineReport
	if err := json.Unmarshal(jsonData, &parsedReport); err != nil {
		t.Fatalf("failed to parse exported JSON: %v", err)
	}
	if parsedReport.TotalThreats != 1 {
		t.Errorf("expected 1 threat in parsed report, got %d", parsedReport.TotalThreats)
	}

	// 6. Test CSV Export
	csvPath := filepath.Join(tempDir, "timeline.csv")
	if err := tm.ExportCSV(csvPath); err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	csvFile, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("failed to open CSV file: %v", err)
	}
	defer csvFile.Close()

	csvReader := csv.NewReader(csvFile)
	records, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV records: %v", err)
	}

	// Header + 3 event rows = 4 rows
	if len(records) != 4 {
		t.Errorf("expected 4 CSV rows (1 header + 3 events), got %d", len(records))
	}
}
