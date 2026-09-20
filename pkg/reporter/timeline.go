// Package reporter provides evidence aggregation, timeline sequencing, and DFIR export engines.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
)

// TimelineEvent records a discrete forensic occurrence along the chronological audit trail.
type TimelineEvent struct {
	ID          string                  `json:"id"`
	Timestamp   time.Time               `json:"timestamp"`
	Type        string                  `json:"type"` // SYSTEM, THREAT, CARVED_FILE, PACKET_ANOMALY
	Severity    protocols.SeverityLevel `json:"severity"`
	Source      string                  `json:"source"`
	Destination string                  `json:"destination"`
	Protocol    string                  `json:"protocol"`
	Summary     string                  `json:"summary"`
	Details     string                  `json:"details"`
	EvidenceRef string                  `json:"evidence_ref,omitempty"`
}

// TimelineReport represents the complete forensic evidence package ready for export.
type TimelineReport struct {
	ToolName           string                     `json:"tool_name"`
	Version            string                     `json:"version"`
	Investigator       string                     `json:"investigator"`
	GitHubProfile      string                     `json:"github_profile"`
	GeneratedAt        time.Time                  `json:"generated_at"`
	IntegritySHA256    string                     `json:"integrity_sha256"`
	TotalEvents        int                        `json:"total_events"`
	TotalThreats       int                        `json:"total_threats"`
	TotalArtifacts     int                        `json:"total_artifacts"`
	Events             []TimelineEvent            `json:"events"`
	ThreatAlerts       []forensics.ThreatAlert    `json:"threat_alerts"`
	ExtractedArtifacts []forensics.ArtifactRecord `json:"extracted_artifacts"`
}

// TimelineManager manages chronological sequencing and integrity verification of forensic evidence.
type TimelineManager struct {
	mu        sync.RWMutex
	events    []TimelineEvent
	alerts    []forensics.ThreatAlert
	artifacts []forensics.ArtifactRecord
}

// NewTimelineManager creates an initialized forensic timeline aggregator.
func NewTimelineManager() *TimelineManager {
	return &TimelineManager{
		events:    make([]TimelineEvent, 0),
		alerts:    make([]forensics.ThreatAlert, 0),
		artifacts: make([]forensics.ArtifactRecord, 0),
	}
}

// RecordEvent appends an event to the forensic timeline in a thread-safe manner.
func (m *TimelineManager) RecordEvent(event TimelineEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if event.ID == "" {
		event.ID = fmt.Sprintf("EVT-%d", time.Now().UnixNano())
	}
	m.events = append(m.events, event)
}

// RecordThreat registers a threat alert and mirrors it into the chronological event timeline.
func (m *TimelineManager) RecordThreat(alert forensics.ThreatAlert) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.alerts = append(m.alerts, alert)

	var sev protocols.SeverityLevel
	switch alert.Level {
	case forensics.LevelSafe:
		sev = protocols.SeveritySafe
	case forensics.LevelWarning:
		sev = protocols.SeverityWarning
	case forensics.LevelThreat:
		sev = protocols.SeverityThreat
	default:
		sev = protocols.SeverityWarning
	}

	m.events = append(m.events, TimelineEvent{
		ID:          alert.ID,
		Timestamp:   alert.Timestamp,
		Type:        "THREAT",
		Severity:    sev,
		Source:      alert.SourceIP,
		Destination: alert.DestIP,
		Protocol:    alert.Protocol,
		Summary:     alert.Title,
		Details:     fmt.Sprintf("%s | Evidence: %s", alert.Details, alert.Evidence),
		EvidenceRef: alert.ID,
	})
}

// RecordArtifact registers a carved artifact and appends a timeline entry.
func (m *TimelineManager) RecordArtifact(artifact forensics.ArtifactRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.artifacts = append(m.artifacts, artifact)

	var sev protocols.SeverityLevel = protocols.SeveritySafe
	if artifact.ThreatIndicator == forensics.LevelThreat {
		sev = protocols.SeverityThreat
	} else if artifact.ThreatIndicator == forensics.LevelWarning {
		sev = protocols.SeverityWarning
	}

	m.events = append(m.events, TimelineEvent{
		ID:          artifact.ID,
		Timestamp:   artifact.Timestamp,
		Type:        "CARVED_FILE",
		Severity:    sev,
		Source:      fmt.Sprintf("%s:%d", artifact.SourceIP, artifact.SourcePort),
		Destination: fmt.Sprintf("%s:%d", artifact.DestIP, artifact.DestPort),
		Protocol:    artifact.Protocol,
		Summary:     fmt.Sprintf("Carved File: %s (%d bytes, %s)", artifact.Filename, artifact.SizeBytes, artifact.MIMEType),
		Details:     fmt.Sprintf("SHA256: %s | MD5: %s | Path: %s", artifact.SHA256, artifact.MD5, artifact.FilePath),
		EvidenceRef: artifact.SHA256,
	})
}

// GenerateReport produces a sorted, integrity-hashed DFIR evidence report.
func (m *TimelineManager) GenerateReport() TimelineReport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Clone events and sort chronologically
	events := make([]TimelineEvent, len(m.events))
	copy(events, m.events)

	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	alerts := make([]forensics.ThreatAlert, len(m.alerts))
	copy(alerts, m.alerts)

	artifacts := make([]forensics.ArtifactRecord, len(m.artifacts))
	copy(artifacts, m.artifacts)

	now := time.Now()

	// Compute integrity hash across all event IDs, timestamps, and evidence refs
	hasher := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(hasher, "%s|%d|%s|%s|%s\n", ev.ID, ev.Timestamp.UnixNano(), ev.Type, ev.Summary, ev.EvidenceRef)
	}
	for _, art := range artifacts {
		fmt.Fprintf(hasher, "%s|%s|%d\n", art.SHA256, art.MD5, art.SizeBytes)
	}
	integrityHash := hex.EncodeToString(hasher.Sum(nil))

	return TimelineReport{
		ToolName:           "NetForensics",
		Version:            "v1.0.0",
		Investigator:       "Ahmad",
		GitHubProfile:      "https://github.com/cys-dexter",
		GeneratedAt:        now,
		IntegritySHA256:    integrityHash,
		TotalEvents:        len(events),
		TotalThreats:       len(alerts),
		TotalArtifacts:     len(artifacts),
		Events:             events,
		ThreatAlerts:       alerts,
		ExtractedArtifacts: artifacts,
	}
}

// Events returns a snapshot copy of current events.
func (m *TimelineManager) Events() []TimelineEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]TimelineEvent, len(m.events))
	copy(events, m.events)
	return events
}
