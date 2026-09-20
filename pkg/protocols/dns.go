// Package protocols contains protocol decoders for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package protocols

import (
	"math"
	"strings"

	"github.com/google/gopacket/layers"
)

// ParseDNS extracts structured DNS query/response data from a layers.DNS pointer.
func ParseDNS(dns *layers.DNS) *DNSEvent {
	if dns == nil {
		return nil
	}

	ev := &DNSEvent{
		ID:           dns.ID,
		QR:           dns.QR,
		OpCode:       dns.OpCode.String(),
		ResponseCode: dns.ResponseCode.String(),
		Questions:    make([]DNSQuestion, 0, len(dns.Questions)),
		Answers:      make([]string, 0, len(dns.Answers)),
	}

	if len(dns.Questions) > 0 {
		ev.QueryName = string(dns.Questions[0].Name)
		ev.QueryType = dns.Questions[0].Type.String()
		for _, q := range dns.Questions {
			ev.Questions = append(ev.Questions, DNSQuestion{
				Name:  string(q.Name),
				Type:  q.Type.String(),
				Class: q.Class.String(),
			})
		}
	}

	for _, a := range dns.Answers {
		if a.TTL > 0 && ev.TTL == 0 {
			ev.TTL = a.TTL
		}
		if a.IP != nil {
			ev.Answers = append(ev.Answers, a.IP.String())
		} else if len(a.TXTs) > 0 {
			for _, txt := range a.TXTs {
				ev.Answers = append(ev.Answers, string(txt))
			}
		} else if len(a.CNAME) > 0 {
			ev.Answers = append(ev.Answers, string(a.CNAME))
		}
	}

	return ev
}

// ExtractSubdomain splits an FQDN and returns the leftmost subdomain prefix,
// omitting the root and TLD/SLD if possible.
// e.g. "a9f8b7c6d5e4.tunnel.evil.com." -> "a9f8b7c6d5e4.tunnel"
func ExtractSubdomain(fqdn string) string {
	cleaned := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	parts := strings.Split(cleaned, ".")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], ".")
}

// CalculateShannonEntropy computes the Shannon entropy in bits per character:
// H(X) = -sum( P(x) * log2(P(x)) )
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
