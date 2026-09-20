// Package ui provides the interactive terminal user interface for NetForensics.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package ui

import (
	"fmt"
	"time"

	"netforensics/pkg/capture"
	"netforensics/pkg/forensics"
	"netforensics/pkg/reassembly"
	"netforensics/pkg/reporter"

	"github.com/rivo/tview"
)

// TUI manages the full-screen terminal interactive dashboard.
type TUI struct {
	app             *tview.Application
	pages           *tview.Pages
	mainLayout      *tview.Flex
	packetsTable    *tview.Table
	alertsTable     *tview.Table
	artifactsTable  *tview.Table
	timelineTable   *tview.Table
	statsView       *tview.TextView
	captureEngine   *capture.Engine
	forensicsEngine *forensics.Engine
	carver          *reassembly.Carver
	timeline        *reporter.TimelineManager
	focusIndex      int
	stopChan        chan struct{}
}

// NewTUI initializes and configures the terminal interface.
func NewTUI(
	capEng *capture.Engine,
	forEng *forensics.Engine,
	carver *reassembly.Carver,
	tm *reporter.TimelineManager,
) *TUI {
	ui := &TUI{
		app:             tview.NewApplication(),
		pages:           tview.NewPages(),
		captureEngine:   capEng,
		forensicsEngine: forEng,
		carver:          carver,
		timeline:        tm,
		focusIndex:      0,
		stopChan:        make(chan struct{}),
	}

	header := ui.createHeaderView()
	ui.packetsTable = ui.createPacketsTable()
	ui.alertsTable = ui.createAlertsTable()
	ui.artifactsTable = ui.createArtifactsTable()
	ui.timelineTable = ui.createTimelineTable()
	footer := ui.createFooterView()

	// Upper split: Packets stream (60%) and Alerts (40%)
	upperSplit := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(ui.packetsTable, 0, 3, true).
		AddItem(ui.alertsTable, 0, 2, false)

	// Lower split: Carved Artifacts (50%) and Evidence Timeline (50%)
	lowerSplit := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(ui.artifactsTable, 0, 1, false).
		AddItem(ui.timelineTable, 0, 1, false)

	// Main vertical layout
	ui.mainLayout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 2, 0, false).
		AddItem(upperSplit, 0, 3, true).
		AddItem(lowerSplit, 0, 2, false).
		AddItem(footer, 1, 0, false)

	ui.pages.AddPage("main", ui.mainLayout, true, true)
	ui.app.SetRoot(ui.pages, true)

	ui.setupKeybindings()
	return ui
}

// Run starts the TUI event loop and real-time metric update goroutine.
func (ui *TUI) Run() error {
	go ui.startStatsTicker()
	return ui.app.Run()
}

// Stop terminates the TUI and releases resources.
func (ui *TUI) Stop() {
	close(ui.stopChan)
	ui.app.Stop()
}

// startStatsTicker refreshes the top metrics card twice a second.
func (ui *TUI) startStatsTicker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ui.stopChan:
			return
		case <-ticker.C:
			snap := ui.captureEngine.Stats().Snapshot()
			_, safe, warning, threat := ui.forensicsEngine.AlertCounts()
			carvedCount := len(ui.carver.GetCarvedArtifacts())

			bytesFormatted := formatBytes(snap.TotalBytes)

			text := fmt.Sprintf(
				" [white]Packets: [lime]%d[-:-] | [white]Bytes: [cyan]%s[-:-] | [white]Rate: [yellow]%.0f pkt/s (%.1f KB/s)[-:-] | [white]Carved Files: [magenta]%d[-:-] | [white]Threat Status: [green]🟢 %d Safe[-:-] [yellow]🟡 %d Warning[-:-] [red]🔴 %d Threat Detected[-:-] ",
				snap.TotalPackets,
				bytesFormatted,
				snap.PacketsPerSec,
				snap.BytesPerSec/1024.0,
				carvedCount,
				safe,
				warning,
				threat,
			)

			ui.app.QueueUpdateDraw(func() {
				ui.statsView.SetText(text)
			})
		}
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
