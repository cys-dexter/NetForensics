// NetForensics: Enterprise-Grade Network Forensics & PCAP Artifact Collector
//
// Author / Developer Name: Ahmad
// GitHub Profile: cys-dexter (https://github.com/cys-dexter)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"netforensics/pkg/capture"
	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
	"netforensics/pkg/reassembly"
	"netforensics/pkg/reporter"
	"netforensics/pkg/ui"

	"golang.org/x/term"
)

const (
	Version   = "1.0.0"
	Author    = "Ahmad"
	GitHubURL = "https://github.com/cys-dexter"
)

var banner = fmt.Sprintf(`
███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██╔██╗ ██║█████╗     ██║   █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
   Enterprise Network Forensics & PCAP Artifact Collector | DFIR Investigation Suite
   Developer: %s | GitHub: %s | Version: %s
`, Author, GitHubURL, Version)

func main() {
	pcapPath := flag.String("r", "", "Path to offline .pcap or .pcapng file for forensic analysis")
	iface := flag.String("i", "", "Live network interface name to monitor (e.g. eth0, any)")
	bpfFilter := flag.String("bpf", "", "Berkeley Packet Filter expression (e.g. 'tcp port 80 or udp port 53')")
	artifactsDir := flag.String("out-dir", "./extracted_artifacts", "Target directory to write carved files")
	timelinePath := flag.String("timeline", "", "Output path for forensic event timeline (e.g. evidence_timeline.json)")
	exportFmt := flag.String("o", "json", "Timeline export format ('json' or 'csv')")
	headless := flag.Bool("headless", false, "Run in non-interactive CLI mode (ideal for SOC automation & scripts)")
	verbose := flag.Bool("v", false, "Enable verbose packet inspection logging")
	showVersion := flag.Bool("version", false, "Print version, author information, and exit")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Analyze offline PCAP file with interactive TUI:\n")
		fmt.Fprintf(os.Stderr, "  netforensics -r suspicious_traffic.pcap\n\n")
		fmt.Fprintf(os.Stderr, "  # Automated headless PCAP analysis with JSON timeline export:\n")
		fmt.Fprintf(os.Stderr, "  netforensics -r malware_c2.pcapng -headless -timeline evidence.json -o json\n\n")
		fmt.Fprintf(os.Stderr, "  # Live capture on eth0 filtering DNS and HTTP:\n")
		fmt.Fprintf(os.Stderr, "  sudo netforensics -i eth0 -bpf 'port 53 or port 80'\n\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("NetForensics v%s\nAuthor: %s\nGitHub: %s\n", Version, Author, GitHubURL)
		os.Exit(0)
	}

	if *pcapPath == "" && *iface == "" {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintln(os.Stderr, "\n[!] Error: You must specify either an offline capture file (-r) or a live interface (-i).")
		fmt.Fprintln(os.Stderr, "    Run with -h or --help for full usage instructions.")
		os.Exit(1)
	}

	// Auto-detect non-TTY environment (redirected stdout or CI/pipeline)
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	runHeadless := *headless || !isTTY

	// Initialize File Carver
	absArtifactsDir, err := filepath.Abs(*artifactsDir)
	if err != nil {
		absArtifactsDir = *artifactsDir
	}
	carver, err := reassembly.NewCarver(absArtifactsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error initializing file carver: %v\n", err)
		os.Exit(1)
	}

	// Initialize Forensics Threat Engine & Stream Manager
	forensicsEngine := forensics.NewEngine()
	streamManager := reassembly.NewStreamManager(carver)
	defer streamManager.Close()

	// Initialize Timeline Manager
	timelineManager := reporter.NewTimelineManager()

	// Record session start event
	sourceDesc := *pcapPath
	if sourceDesc == "" {
		sourceDesc = fmt.Sprintf("live interface %s", *iface)
	}
	timelineManager.RecordEvent(reporter.TimelineEvent{
		Timestamp:   time.Now(),
		Type:        "SYSTEM",
		Severity:    protocols.SeveritySafe,
		Source:      "NetForensics Engine",
		Destination: sourceDesc,
		Protocol:    "SYSTEM",
		Summary:     fmt.Sprintf("Forensic capture session started (Source: %s)", sourceDesc),
		Details:     fmt.Sprintf("Artifacts Directory: %s | BPF Filter: %q", absArtifactsDir, *bpfFilter),
	})

	// Configure Packet Capture Engine
	capCfg := capture.DefaultConfig()
	capCfg.PCAPFile = *pcapPath
	capCfg.Interface = *iface
	capCfg.BPFFilter = *bpfFilter

	capEngine := capture.NewEngine(capCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS Signals (SIGINT / SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Completion channel for offline reading
	doneChan := make(chan struct{})

	// Wire Threat & Artifact Subscriptions to Timeline
	forensicsEngine.SubscribeAlerts(func(alert forensics.ThreatAlert) {
		timelineManager.RecordThreat(alert)
	})
	carver.SubscribeArtifacts(func(art forensics.ArtifactRecord) {
		timelineManager.RecordArtifact(art)
	})

	if runHeadless {
		fmt.Print(banner)
		fmt.Printf("\n[*] NetForensics Forensic Engine Activated\n")
		fmt.Printf("[*] Ingestion Source:     %s\n", sourceDesc)
		fmt.Printf("[*] Carving Directory:    %s\n", absArtifactsDir)
		if *bpfFilter != "" {
			fmt.Printf("[*] BPF Filter:           %s\n", *bpfFilter)
		}
		fmt.Printf("[*] Running Mode:         Non-Interactive CLI (Headless)\n\n")

		// Print live alerts to stdout
		forensicsEngine.SubscribeAlerts(func(alert forensics.ThreatAlert) {
			badge := alert.Level.Badge()
			fmt.Printf("[%s] [%s] %s -> %s | %s\n    └─ Evidence: %s\n",
				alert.Timestamp.Format("15:04:05.000"),
				badge,
				alert.SourceIP,
				alert.DestIP,
				alert.Title,
				alert.Evidence,
			)
		})

		carver.SubscribeArtifacts(func(art forensics.ArtifactRecord) {
			fmt.Printf("[%s] [💾 CARVED FILE] %s (%d bytes, %s)\n    ├─ SHA256: %s\n    ├─ MD5:    %s\n    └─ Path:   %s\n",
				art.Timestamp.Format("15:04:05.000"),
				art.Filename,
				art.SizeBytes,
				art.MIMEType,
				art.SHA256,
				art.MD5,
				art.FilePath,
			)
		})
	}

	// Start packet capture engine
	if err := capEngine.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to start capture engine: %v\n", err)
		os.Exit(1)
	}

	// Launch Pipeline Processing Worker
	var packetCounter uint64
	var tuiInstance *ui.TUI

	if !runHeadless {
		tuiInstance = ui.NewTUI(capEngine, forensicsEngine, carver, timelineManager)

		// Mirror alerts and artifacts to TUI
		forensicsEngine.SubscribeAlerts(func(alert forensics.ThreatAlert) {
			tuiInstance.AppendAlert(alert)
		})
		carver.SubscribeArtifacts(func(art forensics.ArtifactRecord) {
			tuiInstance.AppendArtifact(art)
		})
	}

	// Packet Ingestion & Dissection Loop
	go func() {
		for packet := range capEngine.Packets() {
			currentID := atomic.AddUint64(&packetCounter, 1)

			// Dissect packet into structured network event
			netEv := protocols.ParsePacket(packet)
			if netEv == nil {
				continue
			}

			// Feed TCP segments into stream reassembly
			if netEv.TCPFlags.IsTCP {
				streamManager.IngestPacket(packet)

				// Fast-path HTTP payload carving
				if netEv.HTTPEvent != nil && len(netEv.HTTPEvent.Body) > 0 {
					filename := netEv.HTTPEvent.Filename
					if filename == "" {
						filename = fmt.Sprintf("http_%s_%d", netEv.Flow.DstIP, netEv.Timestamp.Unix())
					}
					_, _ = carver.CarvePayload(netEv.HTTPEvent.Body, netEv.Flow, filename, netEv.Timestamp)
				}
			}

			// Inspect for forensic anomalies & threat patterns
			alert := forensicsEngine.ProcessEvent(netEv)

			// Prepare packet summary
			proto := netEv.Flow.Proto
			info := ""
			if netEv.DNSEvent != nil {
				proto = "DNS"
				if netEv.DNSEvent.QR {
					info = fmt.Sprintf("DNS Resp: %s", strings.Join(netEv.DNSEvent.Answers, ", "))
				} else {
					info = fmt.Sprintf("DNS Query: %s (%s)", netEv.DNSEvent.QueryName, netEv.DNSEvent.QueryType)
				}
			} else if netEv.HTTPEvent != nil {
				proto = "HTTP"
				if netEv.HTTPEvent.IsRequest {
					info = fmt.Sprintf("HTTP %s %s", netEv.HTTPEvent.Method, netEv.HTTPEvent.URI)
				} else {
					info = fmt.Sprintf("HTTP %d %s", netEv.HTTPEvent.StatusCode, netEv.HTTPEvent.StatusMessage)
				}
			} else if netEv.TLSSNI != "" {
				proto = "TLS"
				info = fmt.Sprintf("TLS SNI: %s", netEv.TLSSNI)
			} else if netEv.ARPEvent != nil {
				proto = "ARP"
				info = fmt.Sprintf("ARP %s: %s is at %s", netEv.ARPEvent.Operation, netEv.ARPEvent.SenderIP, netEv.ARPEvent.SenderMAC)
			} else if netEv.TCPFlags.IsTCP {
				flags := []string{}
				if netEv.TCPFlags.SYN {
					flags = append(flags, "SYN")
				}
				if netEv.TCPFlags.ACK {
					flags = append(flags, "ACK")
				}
				if netEv.TCPFlags.FIN {
					flags = append(flags, "FIN")
				}
				if netEv.TCPFlags.RST {
					flags = append(flags, "RST")
				}
				if netEv.TCPFlags.PSH {
					flags = append(flags, "PSH")
				}
				if netEv.TCPFlags.URG {
					flags = append(flags, "URG")
				}
				info = fmt.Sprintf("TCP Flags: [%s] Seq=%d Ack=%d", strings.Join(flags, ","), netEv.TCPFlags.Seq, netEv.TCPFlags.Ack)
			}

			summary := protocols.PacketSummary{
				ID:        currentID,
				Timestamp: netEv.Timestamp,
				SrcIP:     netEv.Flow.SrcIP,
				DstIP:     netEv.Flow.DstIP,
				SrcPort:   netEv.Flow.SrcPort,
				DstPort:   netEv.Flow.DstPort,
				Protocol:  proto,
				Length:    netEv.Length,
				Info:      info,
			}

			if tuiInstance != nil {
				tuiInstance.AppendPacket(summary)
			} else if *verbose {
				fmt.Printf("[%06d] %s | %-5s | %s:%d -> %s:%d | %s\n",
					summary.ID,
					summary.Timestamp.Format("15:04:05.000"),
					summary.Protocol,
					summary.SrcIP, summary.SrcPort,
					summary.DstIP, summary.DstPort,
					summary.Info,
				)
			}

			// If alert was generated, record in timeline
			if alert != nil && tuiInstance != nil {
				tuiInstance.AppendAlert(*alert)
			}
		}

		// When offline PCAP reading reaches EOF
		if !capEngine.IsLive() {
			time.Sleep(100 * time.Millisecond)
			streamManager.FlushComplete()
			close(doneChan)
		}
	}()

	// Run TUI or Headless Waiter
	if !runHeadless {
		go func() {
			select {
			case <-sigChan:
			case <-doneChan:
			}
			if tuiInstance != nil {
				tuiInstance.Stop()
			}
		}()

		if err := tuiInstance.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] TUI Error: %v\n", err)
		}
	} else {
		// Wait for signal or completion
		select {
		case <-sigChan:
			fmt.Println("\n[*] Interrupted by user. Finalizing forensic evidence...")
		case <-doneChan:
			fmt.Println("\n[+] Offline PCAP parsing complete. Finalizing forensic evidence...")
		}
	}

	// Clean Shutdown & Evidence Finalization
	cancel()
	streamManager.FlushComplete()

	// Generate Final Evidence Report
	report := timelineManager.GenerateReport()

	// Export Timeline if requested or if output path specified
	if *timelinePath != "" {
		switch strings.ToLower(*exportFmt) {
		case "csv":
			if err := timelineManager.ExportCSV(*timelinePath); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to export CSV timeline: %v\n", err)
			} else {
				fmt.Printf("\n[+] Forensic timeline successfully exported to CSV: %s\n", *timelinePath)
			}
		default:
			if err := timelineManager.ExportJSON(*timelinePath); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to export JSON timeline: %v\n", err)
			} else {
				fmt.Printf("\n[+] Forensic timeline successfully exported to JSON: %s\n", *timelinePath)
			}
		}
	}

	// Final Summary Report
	stats := capEngine.Stats().Snapshot()
	fmt.Printf("\n================================================================================\n")
	fmt.Printf("                    NETFORENSICS DFIR INVESTIGATION SUMMARY                    \n")
	fmt.Printf("================================================================================\n")
	fmt.Printf("  Lead Investigator:    %s\n", Author)
	fmt.Printf("  GitHub Reference:     %s\n", GitHubURL)
	fmt.Printf("  Session Duration:     %v\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("  Packets Ingested:     %d (%.0f pkt/s)\n", stats.TotalPackets, stats.PacketsPerSec)
	fmt.Printf("  Traffic Volume:       %d bytes\n", stats.TotalBytes)
	fmt.Printf("  Carved Artifacts:     %d files (Saved to: %s)\n", report.TotalArtifacts, absArtifactsDir)
	fmt.Printf("  Forensic Alerts:      %d detected\n", report.TotalThreats)
	fmt.Printf("  Timeline Events:      %d chronological records\n", report.TotalEvents)
	fmt.Printf("  Evidence Hash (SHA):  %s\n", report.IntegritySHA256)
	fmt.Printf("================================================================================\n")
}
