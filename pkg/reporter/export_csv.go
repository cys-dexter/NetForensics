// Package reporter provides CSV export capabilities for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

// ExportCSV writes the forensic timeline to an RFC 4180 compliant CSV file.
func (m *TimelineManager) ExportCSV(filePath string) error {
	report := m.GenerateReport()

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file %s: %w", filePath, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write metadata header comment / row
	header := []string{
		"Event ID",
		"Timestamp (UTC)",
		"Type",
		"Severity",
		"Source",
		"Destination",
		"Protocol",
		"Summary",
		"Details",
		"Evidence Ref",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, ev := range report.Events {
		row := []string{
			ev.ID,
			ev.Timestamp.UTC().Format(time.RFC3339Nano),
			ev.Type,
			string(ev.Severity),
			ev.Source,
			ev.Destination,
			ev.Protocol,
			ev.Summary,
			ev.Details,
			ev.EvidenceRef,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}
