// Package protocols provides HTTP dissectors and artifact carving metadata.
// Author: Ahmad (https://github.com/cys-dexter)
package protocols

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// HTTPEvent represents dissected HTTP forensic metadata.
type HTTPEvent struct {
	IsRequest     bool
	Method        string
	Host          string
	URI           string
	UserAgent     string
	StatusCode    int
	StatusMessage string
	ContentType   string
	ContentLength int64
	Filename      string
	Body          []byte
	Headers       map[string]string
}

var contentDispositionRegex = regexp.MustCompile(`(?i)filename\*?=(?:UTF-8'')?"?([^";]+)"?`)

// ParseHTTPPayload attempts to decode an HTTP request or response from raw payload data.
func ParseHTTPPayload(payload []byte, srcPort, dstPort uint16) *HTTPEvent {
	if len(payload) < 4 {
		return nil
	}

	// Check if this resembles an HTTP request (GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH)
	isReq := bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("PUT ")) ||
		bytes.HasPrefix(payload, []byte("DELETE ")) ||
		bytes.HasPrefix(payload, []byte("HEAD ")) ||
		bytes.HasPrefix(payload, []byte("OPTIONS ")) ||
		bytes.HasPrefix(payload, []byte("PATCH "))

	// Check if this resembles an HTTP response (HTTP/1.0, HTTP/1.1)
	isResp := bytes.HasPrefix(payload, []byte("HTTP/1.0 ")) || bytes.HasPrefix(payload, []byte("HTTP/1.1 "))

	if !isReq && !isResp {
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(payload))

	if isReq {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return parseHTTPFallback(payload, true)
		}

		headers := make(map[string]string)
		for k, v := range req.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
			req.Body.Close()
		}

		host := req.Host
		if host == "" {
			host = req.Header.Get("Host")
		}

		return &HTTPEvent{
			IsRequest:     true,
			Method:        req.Method,
			Host:          host,
			URI:           req.URL.String(),
			UserAgent:     req.UserAgent(),
			ContentType:   req.Header.Get("Content-Type"),
			ContentLength: req.ContentLength,
			Filename:      extractFilename(req.URL.Path, req.Header.Get("Content-Disposition")),
			Body:          body,
			Headers:       headers,
		}
	}

	// Response
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return parseHTTPFallback(payload, false)
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
		resp.Body.Close()
	}

	return &HTTPEvent{
		IsRequest:     false,
		StatusCode:    resp.StatusCode,
		StatusMessage: resp.Status,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Filename:      extractFilename("", resp.Header.Get("Content-Disposition")),
		Body:          body,
		Headers:       headers,
	}
}

// extractFilename identifies target filenames from Content-Disposition header or URI path.
func extractFilename(rawPath, contentDisposition string) string {
	if contentDisposition != "" {
		matches := contentDispositionRegex.FindStringSubmatch(contentDisposition)
		if len(matches) > 1 {
			cleaned := strings.TrimSpace(matches[1])
			cleaned = path.Base(cleaned)
			if cleaned != "." && cleaned != "/" && cleaned != "" {
				return cleaned
			}
		}
	}

	if rawPath != "" {
		u, err := url.PathUnescape(rawPath)
		if err == nil {
			base := path.Base(u)
			if base != "." && base != "/" && base != "" && strings.Contains(base, ".") {
				return base
			}
		}
	}
	return ""
}

// parseHTTPFallback provides a resilient string-based parser if ReadRequest/ReadResponse encounters truncated frames.
func parseHTTPFallback(payload []byte, isReq bool) *HTTPEvent {
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return nil
	}

	ev := &HTTPEvent{
		IsRequest: isReq,
		Headers:   make(map[string]string),
	}

	firstLine := strings.Split(lines[0], " ")
	if isReq && len(firstLine) >= 2 {
		ev.Method = firstLine[0]
		ev.URI = firstLine[1]
	} else if !isReq && len(firstLine) >= 2 {
		if code, err := strconv.Atoi(firstLine[1]); err == nil {
			ev.StatusCode = code
		}
		if len(firstLine) >= 3 {
			ev.StatusMessage = strings.Join(firstLine[2:], " ")
		}
	}

	headerEnd := false
	bodyLines := []string{}

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if headerEnd {
			bodyLines = append(bodyLines, line)
			continue
		}
		if line == "" {
			headerEnd = true
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			ev.Headers[k] = v
			switch strings.ToLower(k) {
			case "host":
				ev.Host = v
			case "user-agent":
				ev.UserAgent = v
			case "content-type":
				ev.ContentType = v
			case "content-length":
				if cl, err := strconv.ParseInt(v, 10, 64); err == nil {
					ev.ContentLength = cl
				}
			}
		}
	}

	if len(bodyLines) > 0 {
		ev.Body = []byte(strings.Join(bodyLines, "\r\n"))
	}
	ev.Filename = extractFilename(ev.URI, ev.Headers["Content-Disposition"])
	return ev
}
