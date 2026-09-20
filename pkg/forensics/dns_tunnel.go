// Package forensics provides DNS tunneling and exfiltration pattern analysis.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"netforensics/pkg/protocols"
)

var (
	hexPattern    = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)
	base32Pattern = regexp.MustCompile(`^[a-zA-Z2-7=]{24,}$`)
	base64Pattern = regexp.MustCompile(`^[a-zA-Z0-9+/=]{24,}$`)
)

// DNSTunnelDetector inspects DNS queries for C2 and data exfiltration patterns.
type DNSTunnelDetector struct {
	mu             sync.Mutex
	domainTracker  map[string]*domainStats
	entropyLimit   float64
	labelLenLimit  int
	windowDuration time.Duration
}

type domainStats struct {
	firstSeen   time.Time
	lastSeen    time.Time
	queryCount  int
	highEntropy int
}

// NewDNSTunnelDetector instantiates the DNS anomaly engine.
func NewDNSTunnelDetector() *DNSTunnelDetector {
	return &DNSTunnelDetector{
		domainTracker:  make(map[string]*domainStats),
		entropyLimit:   3.75,
		labelLenLimit:  35,
		windowDuration: 5 * time.Minute,
	}
}

// InspectQuery analyzes a DNS event and returns a ThreatAlert if anomalous indicators are detected.
func (d *DNSTunnelDetector) InspectQuery(srcIP, dstIP string, dnsEv *protocols.DNSEvent, timestamp time.Time) *ThreatAlert {
	if dnsEv == nil || dnsEv.QueryName == "" {
		return nil
	}

	qName := strings.TrimSuffix(strings.ToLower(dnsEv.QueryName), ".")
	labels := strings.Split(qName, ".")
	if len(labels) < 2 {
		return nil
	}

	baseDomain := getBaseDomain(labels)
	subdomainPart := strings.Join(labels[:len(labels)-2], ".")

	// Calculate metrics
	subdomainEntropy := protocols.CalculateShannonEntropy(subdomainPart)
	maxLabelLen := 0
	hasEncodingPattern := false

	for _, l := range labels[:len(labels)-1] {
		if len(l) > maxLabelLen {
			maxLabelLen = len(l)
		}
		if hexPattern.MatchString(l) || base32Pattern.MatchString(l) || (len(l) > 30 && base64Pattern.MatchString(l)) {
			hasEncodingPattern = true
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update domain stats tracker
	stats, exists := d.domainTracker[baseDomain]
	if !exists {
		stats = &domainStats{firstSeen: timestamp, lastSeen: timestamp}
		d.domainTracker[baseDomain] = stats
	}
	stats.lastSeen = timestamp
	stats.queryCount++
	if subdomainEntropy >= d.entropyLimit {
		stats.highEntropy++
	}

	// Threat Scoring Heuristics
	var threatScore float64
	var reasons []string

	if subdomainEntropy >= 4.0 {
		threatScore += 0.45
		reasons = append(reasons, fmt.Sprintf("Extremely high Shannon entropy (%.2f bits/char)", subdomainEntropy))
	} else if subdomainEntropy >= d.entropyLimit && len(subdomainPart) > 15 {
		threatScore += 0.30
		reasons = append(reasons, fmt.Sprintf("High entropy (%.2f bits/char)", subdomainEntropy))
	}

	if maxLabelLen >= 45 {
		threatScore += 0.40
		reasons = append(reasons, fmt.Sprintf("Anomalously long subdomain label (%d characters)", maxLabelLen))
	} else if maxLabelLen >= d.labelLenLimit {
		threatScore += 0.25
		reasons = append(reasons, fmt.Sprintf("Subdomain label exceeds baseline length (%d chars)", maxLabelLen))
	}

	if hasEncodingPattern {
		threatScore += 0.35
		reasons = append(reasons, "Encoded payload signature detected (Base32/Hex/Base64 C2 exfiltration format)")
	}

	// TXT record exfiltration check
	if dnsEv.QueryType == "TXT" && dnsEv.QR && len(dnsEv.Answers) > 0 {
		for _, ans := range dnsEv.Answers {
			if len(ans) > 80 && protocols.CalculateShannonEntropy(ans) > 4.2 {
				threatScore += 0.35
				reasons = append(reasons, fmt.Sprintf("Oversized high-entropy TXT answer (%d bytes)", len(ans)))
				break
			}
		}
	}

	// High frequency burst to same base domain with high entropy
	if stats.queryCount >= 5 && float64(stats.highEntropy)/float64(stats.queryCount) > 0.6 {
		threatScore += 0.20
		reasons = append(reasons, fmt.Sprintf("Sustained high-entropy query volume (%d queries to %s)", stats.queryCount, baseDomain))
	}

	if threatScore >= 0.70 {
		return &ThreatAlert{
			ID:         fmt.Sprintf("DNS-TUNNEL-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelThreat,
			Category:   CategoryDNSTunneling,
			Title:      "DNS Tunneling / Data Exfiltration Detected",
			SourceIP:   srcIP,
			DestIP:     dstIP,
			Protocol:   "DNS",
			Details:    fmt.Sprintf("Detected DNS covert channel querying '%s' (Base Domain: %s)", qName, baseDomain),
			Evidence:   strings.Join(reasons, "; "),
			Confidence: min(threatScore, 1.0),
		}
	} else if threatScore >= 0.40 {
		return &ThreatAlert{
			ID:         fmt.Sprintf("DNS-WARN-%d", timestamp.UnixNano()),
			Timestamp:  timestamp,
			Level:      LevelWarning,
			Category:   CategoryDNSTunneling,
			Title:      "Suspicious High-Entropy DNS Activity",
			SourceIP:   srcIP,
			DestIP:     dstIP,
			Protocol:   "DNS",
			Details:    fmt.Sprintf("Elevated entropy query on domain: %s", qName),
			Evidence:   strings.Join(reasons, "; "),
			Confidence: threatScore,
		}
	}

	return nil
}

func getBaseDomain(labels []string) string {
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
