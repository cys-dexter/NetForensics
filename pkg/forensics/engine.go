// Package forensics provides the central threat detection and correlation engine.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"sync"

	"netforensics/pkg/protocols"
)

// Engine integrates all anomaly detectors and alert management.
type Engine struct {
	mu           sync.RWMutex
	alerts       []ThreatAlert
	dnsDetector  *DNSTunnelDetector
	arpDetector  *ARPPoisonDetector
	portDetector *PortScanDetector
	alertHooks   []func(ThreatAlert)
}

// NewEngine creates an initialized forensics detection engine.
func NewEngine() *Engine {
	return &Engine{
		alerts:       make([]ThreatAlert, 0),
		dnsDetector:  NewDNSTunnelDetector(),
		arpDetector:  NewARPPoisonDetector(),
		portDetector: NewPortScanDetector(),
		alertHooks:   make([]func(ThreatAlert), 0),
	}
}

// SubscribeAlerts registers a listener triggered whenever a new ThreatAlert is generated.
func (e *Engine) SubscribeAlerts(hook func(ThreatAlert)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alertHooks = append(e.alertHooks, hook)
}

// ProcessEvent dispatches parsed network events to relevant detection engines.
func (e *Engine) ProcessEvent(ev *protocols.NetworkEvent) *ThreatAlert {
	if ev == nil {
		return nil
	}

	var alert *ThreatAlert

	// 1. DNS Anomaly Inspection
	if ev.DNSEvent != nil {
		alert = e.dnsDetector.InspectQuery(ev.Flow.SrcIP, ev.Flow.DstIP, ev.DNSEvent, ev.Timestamp)
	}

	// 2. ARP Poisoning / MITM Inspection
	if alert == nil && ev.ARPEvent != nil {
		alert = e.arpDetector.InspectARP(ev.ARPEvent, ev.Timestamp)
	}

	// 3. Port Scan / TCP Flag Inspection
	if alert == nil && ev.TCPFlags.IsTCP {
		alert = e.portDetector.InspectTCP(ev.Flow, ev.TCPFlags, ev.Timestamp)
	}

	if alert != nil {
		e.RecordAlert(*alert)
	}

	return alert
}

// RecordAlert safely stores an alert and notifies listeners.
func (e *Engine) RecordAlert(alert ThreatAlert) {
	e.mu.Lock()
	e.alerts = append(e.alerts, alert)
	hooks := append([]func(ThreatAlert){}, e.alertHooks...)
	e.mu.Unlock()

	for _, hook := range hooks {
		hook(alert)
	}
}

// GetAlerts returns a snapshot of all detected alerts.
func (e *Engine) GetAlerts() []ThreatAlert {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]ThreatAlert, len(e.alerts))
	copy(out, e.alerts)
	return out
}

// AlertCounts returns the current alert count breakdown by severity.
func (e *Engine) AlertCounts() (total, safe, warning, threat int) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	total = len(e.alerts)
	for _, a := range e.alerts {
		switch a.Level {
		case LevelSafe:
			safe++
		case LevelWarning:
			warning++
		case LevelThreat:
			threat++
		}
	}
	return
}
