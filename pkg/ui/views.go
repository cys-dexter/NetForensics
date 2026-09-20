// Package ui provides interactive TUI components for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package ui

import (
	"fmt"

	"netforensics/pkg/forensics"
	"netforensics/pkg/protocols"
	"netforensics/pkg/reporter"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// createHeaderView builds the top branding banner and real-time statistics bar.
func (ui *TUI) createHeaderView() *tview.Flex {
	header := tview.NewFlex().SetDirection(tview.FlexRow)

	// Branding Banner
	banner := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	bannerText := "[::b][white]NetForensics [cyan]v1.0.0[::-]  |  " +
		"[yellow]Enterprise Network Forensics & PCAP Artifact Collector[::-]  |  " +
		"[green]Author: [white]Ahmad[::-]  |  [blue]GitHub: [white]https://github.com/cys-dexter[::-]"
	banner.SetText(bannerText)
	banner.SetBackgroundColor(tcell.ColorBlack)

	// Metrics Bar
	statsView := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	statsView.SetBackgroundColor(tcell.ColorDarkBlue)
	ui.statsView = statsView

	header.AddItem(banner, 1, 0, false)
	header.AddItem(statsView, 1, 0, false)
	return header
}

// createPacketsTable initializes the live packet stream table.
func (ui *TUI) createPacketsTable() *tview.Table {
	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetSeparator(tview.Borders.Vertical)

	headers := []string{"#", "Time", "Source", "Destination", "Proto", "Len", "Summary / Forensic Info"}
	for col, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[::b]%s", h)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		table.SetCell(0, col, cell)
	}

	table.SetBorder(true).
		SetTitle(" [1] Live Packets Stream (Press '1' to Focus) ").
		SetTitleColor(tcell.ColorAqua).
		SetBorderColor(tcell.ColorDarkGray)

	return table
}

// createAlertsTable initializes the threat detection and anomalies panel.
func (ui *TUI) createAlertsTable() *tview.Table {
	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetSeparator(tview.Borders.Vertical)

	headers := []string{"Severity", "Time", "Category", "Source", "Target", "Title", "Evidence"}
	for col, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[::b]%s", h)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		table.SetCell(0, col, cell)
	}

	table.SetBorder(true).
		SetTitle(" [2] Forensic Threat Alerts (Press '2' to Focus) ").
		SetTitleColor(tcell.ColorOrange).
		SetBorderColor(tcell.ColorDarkGray)

	return table
}

// createArtifactsTable initializes the carved files and forensic hash table.
func (ui *TUI) createArtifactsTable() *tview.Table {
	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetSeparator(tview.Borders.Vertical)

	headers := []string{"Threat", "Filename", "Size (Bytes)", "MIME Type", "SHA-256 Checksum", "Source Flow"}
	for col, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[::b]%s", h)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		table.SetCell(0, col, cell)
	}

	table.SetBorder(true).
		SetTitle(" [3] Carved Artifacts & Hashes (Press '3' or 'f' to Focus) ").
		SetTitleColor(tcell.ColorGreen).
		SetBorderColor(tcell.ColorDarkGray)

	return table
}

// createTimelineTable initializes the chronological forensic timeline table.
func (ui *TUI) createTimelineTable() *tview.Table {
	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetSeparator(tview.Borders.Vertical)

	headers := []string{"Time", "Type", "Severity", "Source", "Destination", "Summary", "Details"}
	for col, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[::b]%s", h)).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		table.SetCell(0, col, cell)
	}

	table.SetBorder(true).
		SetTitle(" [4] Evidence Timeline (Press '4' to Focus) ").
		SetTitleColor(tcell.ColorPurple).
		SetBorderColor(tcell.ColorDarkGray)

	return table
}

// createFooterView builds the bottom keyboard shortcut navigation bar.
func (ui *TUI) createFooterView() *tview.TextView {
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	footerText := "[::b][yellow][Tab][white] Cycle Panes  |  " +
		"[yellow][1-4][white] Select View  |  " +
		"[yellow][e][white] Export Timeline (JSON/CSV)  |  " +
		"[yellow][f][white] View Artifacts  |  " +
		"[yellow][?][white] Help  |  " +
		"[yellow][q][white] Quit & Save Evidence[::-]"

	footer.SetText(footerText)
	footer.SetBackgroundColor(tcell.ColorDarkSlateGray)
	return footer
}

// AppendPacket adds a packet row to the packet view table.
func (ui *TUI) AppendPacket(p protocols.PacketSummary) {
	ui.app.QueueUpdateDraw(func() {
		row := ui.packetsTable.GetRowCount()
		// Cap table at 500 rows to ensure optimal rendering performance
		if row > 500 {
			ui.packetsTable.RemoveRow(1)
			row = ui.packetsTable.GetRowCount()
		}

		timeStr := p.Timestamp.Format("15:04:05.000")
		protoColor := tcell.ColorWhite
		switch p.Protocol {
		case "TCP":
			protoColor = tcell.ColorDodgerBlue
		case "UDP":
			protoColor = tcell.ColorLightCyan
		case "DNS":
			protoColor = tcell.ColorOrange
		case "HTTP":
			protoColor = tcell.ColorLimeGreen
		case "ARP":
			protoColor = tcell.ColorHotPink
		}

		srcStr := p.SrcIP
		if p.SrcPort > 0 {
			srcStr = fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)
		}
		dstStr := p.DstIP
		if p.DstPort > 0 {
			dstStr = fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)
		}

		ui.packetsTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", p.ID)).SetTextColor(tcell.ColorGray))
		ui.packetsTable.SetCell(row, 1, tview.NewTableCell(timeStr).SetTextColor(tcell.ColorLightGray))
		ui.packetsTable.SetCell(row, 2, tview.NewTableCell(srcStr).SetTextColor(tcell.ColorWhite))
		ui.packetsTable.SetCell(row, 3, tview.NewTableCell(dstStr).SetTextColor(tcell.ColorWhite))
		ui.packetsTable.SetCell(row, 4, tview.NewTableCell(p.Protocol).SetTextColor(protoColor))
		ui.packetsTable.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", p.Length)).SetTextColor(tcell.ColorSilver))
		ui.packetsTable.SetCell(row, 6, tview.NewTableCell(p.Info).SetTextColor(tcell.ColorWhite))

		// Auto-scroll to bottom if focused on packets table
		ui.packetsTable.ScrollToEnd()
	})
}

// AppendAlert adds a threat alert row to the threat view table.
func (ui *TUI) AppendAlert(alert forensics.ThreatAlert) {
	ui.app.QueueUpdateDraw(func() {
		row := ui.alertsTable.GetRowCount()

		sevColor := tcell.ColorYellow
		badge := "🟡 WARNING"
		if alert.Level == forensics.LevelThreat {
			sevColor = tcell.ColorRed
			badge = "🔴 THREAT"
		} else if alert.Level == forensics.LevelSafe {
			sevColor = tcell.ColorGreen
			badge = "🟢 SAFE"
		}

		timeStr := alert.Timestamp.Format("15:04:05")

		ui.alertsTable.SetCell(row, 0, tview.NewTableCell(badge).SetTextColor(sevColor))
		ui.alertsTable.SetCell(row, 1, tview.NewTableCell(timeStr).SetTextColor(tcell.ColorLightGray))
		ui.alertsTable.SetCell(row, 2, tview.NewTableCell(string(alert.Category)).SetTextColor(tcell.ColorYellow))
		ui.alertsTable.SetCell(row, 3, tview.NewTableCell(alert.SourceIP).SetTextColor(tcell.ColorWhite))
		ui.alertsTable.SetCell(row, 4, tview.NewTableCell(alert.DestIP).SetTextColor(tcell.ColorWhite))
		ui.alertsTable.SetCell(row, 5, tview.NewTableCell(alert.Title).SetTextColor(tcell.ColorWhite))
		ui.alertsTable.SetCell(row, 6, tview.NewTableCell(alert.Evidence).SetTextColor(tcell.ColorSilver))

		ui.alertsTable.ScrollToEnd()
	})
}

// AppendArtifact adds a carved file row to the carved artifacts table.
func (ui *TUI) AppendArtifact(art forensics.ArtifactRecord) {
	ui.app.QueueUpdateDraw(func() {
		row := ui.artifactsTable.GetRowCount()

		badge := "🟢 SAFE"
		color := tcell.ColorGreen
		if art.ThreatIndicator == forensics.LevelThreat {
			badge = "🔴 THREAT"
			color = tcell.ColorRed
		} else if art.ThreatIndicator == forensics.LevelWarning {
			badge = "🟡 WARN"
			color = tcell.ColorYellow
		}

		flowStr := fmt.Sprintf("%s:%d -> %s:%d", art.SourceIP, art.SourcePort, art.DestIP, art.DestPort)

		ui.artifactsTable.SetCell(row, 0, tview.NewTableCell(badge).SetTextColor(color))
		ui.artifactsTable.SetCell(row, 1, tview.NewTableCell(art.Filename).SetTextColor(tcell.ColorWhite))
		ui.artifactsTable.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%d", art.SizeBytes)).SetTextColor(tcell.ColorYellow))
		ui.artifactsTable.SetCell(row, 3, tview.NewTableCell(art.MIMEType).SetTextColor(tcell.ColorAqua))
		ui.artifactsTable.SetCell(row, 4, tview.NewTableCell(art.SHA256).SetTextColor(tcell.ColorSilver))
		ui.artifactsTable.SetCell(row, 5, tview.NewTableCell(flowStr).SetTextColor(tcell.ColorLightGray))

		ui.artifactsTable.ScrollToEnd()
	})
}

// AppendTimeline adds a chronological event to the timeline view.
func (ui *TUI) AppendTimeline(ev reporter.TimelineEvent) {
	ui.app.QueueUpdateDraw(func() {
		row := ui.timelineTable.GetRowCount()

		sevColor := tcell.ColorGreen
		switch ev.Severity {
		case protocols.SeverityWarning:
			sevColor = tcell.ColorYellow
		case protocols.SeverityThreat:
			sevColor = tcell.ColorRed
		}

		timeStr := ev.Timestamp.Format("15:04:05.000")

		ui.timelineTable.SetCell(row, 0, tview.NewTableCell(timeStr).SetTextColor(tcell.ColorLightGray))
		ui.timelineTable.SetCell(row, 1, tview.NewTableCell(ev.Type).SetTextColor(tcell.ColorAqua))
		ui.timelineTable.SetCell(row, 2, tview.NewTableCell(string(ev.Severity)).SetTextColor(sevColor))
		ui.timelineTable.SetCell(row, 3, tview.NewTableCell(ev.Source).SetTextColor(tcell.ColorWhite))
		ui.timelineTable.SetCell(row, 4, tview.NewTableCell(ev.Destination).SetTextColor(tcell.ColorWhite))
		ui.timelineTable.SetCell(row, 5, tview.NewTableCell(ev.Summary).SetTextColor(tcell.ColorWhite))
		ui.timelineTable.SetCell(row, 6, tview.NewTableCell(ev.Details).SetTextColor(tcell.ColorSilver))

		ui.timelineTable.ScrollToEnd()
	})
}
