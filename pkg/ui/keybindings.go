// Package ui provides keyboard interaction handlers and modal dialogs.
// Author: Ahmad (GitHub: https://github.com/cys-dexter)
package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// setupKeybindings binds global application shortcuts and modal controls.
func (ui *TUI) setupKeybindings() {
	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// If a modal page is currently active, let the modal handle input
		if name, _ := ui.pages.GetFrontPage(); name != "main" {
			if event.Key() == tcell.KeyEscape {
				ui.pages.SwitchToPage("main")
				return nil
			}
			return event
		}

		switch event.Key() {
		case tcell.KeyTab:
			ui.cycleFocus(false)
			return nil
		case tcell.KeyBacktab:
			ui.cycleFocus(true)
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q', 'Q':
				ui.app.Stop()
				return nil
			case '1':
				ui.focusIndex = 0
				ui.app.SetFocus(ui.packetsTable)
				return nil
			case '2':
				ui.focusIndex = 1
				ui.app.SetFocus(ui.alertsTable)
				return nil
			case '3':
				ui.focusIndex = 2
				ui.app.SetFocus(ui.artifactsTable)
				return nil
			case '4':
				ui.focusIndex = 3
				ui.app.SetFocus(ui.timelineTable)
				return nil
			case 'e', 'E':
				ui.showExportModal()
				return nil
			case 'f', 'F':
				ui.showArtifactsModal()
				return nil
			case '?':
				ui.showHelpModal()
				return nil
			}
		case tcell.KeyF1:
			ui.showHelpModal()
			return nil
		}

		return event
	})
}

// cycleFocus advances keyboard focus sequentially across UI tables.
func (ui *TUI) cycleFocus(reverse bool) {
	tables := []tview.Primitive{
		ui.packetsTable,
		ui.alertsTable,
		ui.artifactsTable,
		ui.timelineTable,
	}

	if reverse {
		ui.focusIndex--
		if ui.focusIndex < 0 {
			ui.focusIndex = len(tables) - 1
		}
	} else {
		ui.focusIndex++
		if ui.focusIndex >= len(tables) {
			ui.focusIndex = 0
		}
	}

	ui.app.SetFocus(tables[ui.focusIndex])
}

// showExportModal displays an interactive prompt to export the evidence timeline to JSON or CSV.
func (ui *TUI) showExportModal() {
	modal := tview.NewModal().
		SetText("Export Forensic Evidence Timeline\n\nChoose target format to save to disk:").
		AddButtons([]string{"Export JSON", "Export CSV", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonLabel {
			case "Export JSON":
				outPath := "evidence_timeline.json"
				err := ui.timeline.ExportJSON(outPath)
				if err != nil {
					ui.showNoticeModal(fmt.Sprintf("Export Failed: %v", err))
				} else {
					ui.showNoticeModal(fmt.Sprintf("Successfully exported forensic timeline to:\n%s", outPath))
				}
			case "Export CSV":
				outPath := "evidence_timeline.csv"
				err := ui.timeline.ExportCSV(outPath)
				if err != nil {
					ui.showNoticeModal(fmt.Sprintf("Export Failed: %v", err))
				} else {
					ui.showNoticeModal(fmt.Sprintf("Successfully exported forensic timeline to:\n%s", outPath))
				}
			default:
				ui.pages.SwitchToPage("main")
			}
		})

	ui.pages.AddPage("export_modal", modal, true, true)
}

// showArtifactsModal displays an inspector dialog with all carved files and hashes.
func (ui *TUI) showArtifactsModal() {
	artifacts := ui.carver.GetCarvedArtifacts()
	text := fmt.Sprintf("[::b][green]Carved Artifacts Registry (%d Total)[::-]\n\n", len(artifacts))

	if len(artifacts) == 0 {
		text += "[yellow]No files have been carved from unencrypted streams yet.\nWait for HTTP/FTP file transfers to be observed."
	} else {
		for i, a := range artifacts {
			text += fmt.Sprintf("[cyan]#%d: [white]%s [yellow](%d bytes, %s)\n", i+1, a.Filename, a.SizeBytes, a.MIMEType)
			text += fmt.Sprintf("    [silver]Path:   %s\n", a.FilePath)
			text += fmt.Sprintf("    [green]SHA256: %s\n", a.SHA256)
			text += fmt.Sprintf("    [blue]MD5:    %s\n", a.MD5)
			text += fmt.Sprintf("    [yellow]Flow:   %s:%d -> %s:%d (%s)\n\n", a.SourceIP, a.SourcePort, a.DestIP, a.DestPort, a.Protocol)
		}
	}

	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.pages.SwitchToPage("main")
		})

	ui.pages.AddPage("artifacts_modal", modal, true, true)
}

// showNoticeModal displays an informational popup.
func (ui *TUI) showNoticeModal(message string) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.pages.SwitchToPage("main")
		})

	ui.pages.AddPage("notice_modal", modal, true, true)
}

// showHelpModal displays the keyboard navigation cheatsheet.
func (ui *TUI) showHelpModal() {
	helpText := `[::b][cyan]NetForensics v1.0.0 Help & Keybindings[::-]
[yellow]Developed by Ahmad (https://github.com/cys-dexter)[::-]

[green]Navigation Keys:[::-]
  [yellow]Tab / Shift+Tab[::-]  Cycle active pane forward / backward
  [yellow]Arrow Keys[::-]       Scroll up/down through records in active table
  [yellow]1[::-]                Focus Live Packets Stream
  [yellow]2[::-]                Focus Threat Alerts Panel
  [yellow]3[::-]                Focus Carved Artifacts Table
  [yellow]4[::-]                Focus Evidence Timeline

[green]Forensic Commands:[::-]
  [yellow]e[::-]                Export timeline to JSON or RFC 4180 CSV
  [yellow]f[::-]                Inspect carved artifacts and checksums
  [yellow]?[::-] or [yellow]F1[::-]          Show this help dialog
  [yellow]q[::-] or [yellow]Ctrl+C[::-]      Quit NetForensics and finalize logs`

	modal := tview.NewModal().
		SetText(helpText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.pages.SwitchToPage("main")
		})

	ui.pages.AddPage("help_modal", modal, true, true)
}
