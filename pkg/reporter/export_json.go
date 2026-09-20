// Package reporter provides JSON export capabilities for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
)

// ExportJSON writes the TimelineReport to a file in structured, indented JSON.
func (m *TimelineManager) ExportJSON(filePath string) error {
	report := m.GenerateReport()

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal forensic report to JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON forensic report to %s: %w", filePath, err)
	}

	return nil
}

// ToJSONString returns the serialized JSON representation of the report.
func (m *TimelineManager) ToJSONString() (string, error) {
	report := m.GenerateReport()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
