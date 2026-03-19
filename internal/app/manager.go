package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type ManagedTunnel struct {
	Type       string
	Name       string
	Interface  string
	MainConfig string
	ExtraFiles []string
}

func runManager(uiOut *ui.UI, prompter *ui.Prompter, xfrmConfDir string) error {
	uiOut.HR()
	uiOut.Title("Tunnel Manager")
	uiOut.HR()

	tunnels, err := scanTunnels(xfrmConfDir)
	if err != nil {
		return err
	}

	if len(tunnels) == 0 {
		uiOut.Warn("No tunnels found.")
		return nil
	}

	options := make([]ui.Option, len(tunnels))
	for i, t := range tunnels {
		label := fmt.Sprintf("[%s] %s (%s)", t.Type, t.Interface, t.MainConfig)
		options[i] = ui.Option{Label: label, Value: fmt.Sprintf("%d", i)}
	}

	choice := "0"
	if err := askSelectRaw(prompter, "Select a tunnel to manage", append(options, ui.Option{Label: "Cancel", Value: "-1"}), &choice); err != nil {
		return wrapAbort(err)
	}

	if choice == "-1" {
		return nil
	}

	idx := 0
	fmt.Sscanf(choice, "%d", &idx)
	selected := tunnels[idx]

	return manageTunnel(uiOut, prompter, selected)
}

func manageTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	for {
		uiOut.HR()
		uiOut.Title(fmt.Sprintf("Managing: %s (%s)", t.Interface, t.Type))
		uiOut.HR()

		action := "status"
		options := []ui.Option{
			{Label: "1) View Status", Value: "status"},
			{Label: "2) Bring UP", Value: "up"},
			{Label: "3) Bring DOWN", Value: "down"},
			{Label: "4) Edit Config", Value: "edit"},
			{Label: "5) Delete Tunnel", Value: "delete"},
			{Label: "0) Back", Value: "back"},
		}

		if err := askSelectRaw(prompter, "Action", options, &action); err != nil {
			return wrapAbort(err)
		}

		switch action {
		case "status":
			showTunnelStatus(uiOut, t)
		case "up":
			bringTunnelUp(uiOut, t)
		case "down":
			bringTunnelDown(uiOut, t)
		case "edit":
			if err := editTunnelConfig(uiOut, prompter, t); err != nil {
				uiOut.Warn(err.Error())
			}
		case "delete":
			ok, err := askConfirm(prompter, fmt.Sprintf("Delete config files and tear down %s?", t.Interface), false)
			if err != nil {
				return wrapAbort(err)
			}
			if ok {
				deleteTunnel(uiOut, t)
				return nil // return to main menu or exit
			}
		case "back":
			return nil
		}
	}
}

func scanTunnels(xfrmConfDir string) ([]ManagedTunnel, error) {
	var tunnels []ManagedTunnel

	// XFRM
	files, _ := filepath.Glob(filepath.Join(xfrmConfDir, "*.conf"))
	for _, f := range files {
		base := filepath.Base(f)
		iface := strings.TrimSuffix(base, ".conf")
		t := ManagedTunnel{
			Type:       "XFRM",
			Name:       strings.TrimPrefix(iface, "ipsec-"),
			Interface:  iface,
			MainConfig: f,
			ExtraFiles: []string{
				filepath.Join("/etc/swanctl/conf.d", iface+".secrets"),
				filepath.Join("/etc/network/interfaces.d", iface+".cfg"),
			},
		}
		tunnels = append(tunnels, t)
	}

	// WireGuard
	files, _ = filepath.Glob("/etc/wireguard/*.conf")
	for _, f := range files {
		base := filepath.Base(f)
		iface := strings.TrimSuffix(base, ".conf")
		t := ManagedTunnel{
			Type:       "WireGuard",
			Name:       strings.TrimPrefix(iface, "wg-"),
			Interface:  iface,
			MainConfig: f,
		}
		tunnels = append(tunnels, t)
	}

	// AmneziaWG
	files, _ = filepath.Glob("/etc/amnezia/amneziawg/*.conf")
	for _, f := range files {
		base := filepath.Base(f)
		iface := strings.TrimSuffix(base, ".conf")
		t := ManagedTunnel{
			Type:       "AmneziaWG",
			Name:       strings.TrimPrefix(iface, "awg-"),
			Interface:  iface,
			MainConfig: f,
		}
		tunnels = append(tunnels, t)
	}

	// VXLAN & GRE
	files, _ = filepath.Glob("/etc/network/interfaces.d/*.cfg")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(b)
		base := filepath.Base(f)
		iface := strings.TrimSuffix(base, ".cfg")

		// Skip standard XFRM (managed by swanctl .conf)
		if strings.Contains(content, "type xfrm") && !strings.Contains(content, "ip xfrm state") {
			continue
		}

		if strings.Contains(content, "type xfrm") && strings.Contains(content, "ip xfrm state") {
			t := ManagedTunnel{
				Type:       "StaticXFRM",
				Name:       iface,
				Interface:  iface,
				MainConfig: f,
			}
			tunnels = append(tunnels, t)
		} else if strings.Contains(content, "type vxlan") {
			t := ManagedTunnel{
				Type:       "VXLAN",
				Name:       iface,
				Interface:  iface,
				MainConfig: f,
			}
			tunnels = append(tunnels, t)
		} else if strings.Contains(content, "mode gre") || strings.Contains(content, "mode ip6gre") {
			t := ManagedTunnel{
				Type:       "GRE",
				Name:       iface,
				Interface:  iface,
				MainConfig: f,
			}
			tunnels = append(tunnels, t)
		}
	}

	return tunnels, nil
}

func showTunnelStatus(uiOut *ui.UI, t ManagedTunnel) {
	uiOut.Info("Interface status:")
	out, _ := sys.Output("ip", "-d", "link", "show", t.Interface)
	if out == "" {
		fmt.Fprintln(uiOut.Out, "Interface is down or does not exist.")
	} else {
		fmt.Fprintln(uiOut.Out, out)
	}

	out, _ = sys.Output("ip", "addr", "show", t.Interface)
	if out != "" {
		fmt.Fprintln(uiOut.Out, out)
	}

	switch t.Type {
	case "XFRM":
		uiOut.Info("swanctl list-sas:")
		out, _ = sys.Output("swanctl", "--list-sas", "--ike", t.Name)
		fmt.Fprintln(uiOut.Out, out)
	case "StaticXFRM":
		uiOut.Info("ip xfrm state:")
		out, _ = sys.Output("ip", "xfrm", "state")
		fmt.Fprintln(uiOut.Out, out)
		uiOut.Info("ip xfrm policy:")
		out, _ = sys.Output("ip", "xfrm", "policy")
		fmt.Fprintln(uiOut.Out, out)
	case "WireGuard":
		uiOut.Info("wg show:")
		out, _ = sys.Output("wg", "show", t.Interface)
		fmt.Fprintln(uiOut.Out, out)
	case "AmneziaWG":
		uiOut.Info("awg show:")
		out, _ = sys.Output("awg", "show", t.Interface)
		fmt.Fprintln(uiOut.Out, out)
	}
}

func bringTunnelUp(uiOut *ui.UI, t ManagedTunnel) {
	uiOut.Info("Bringing up " + t.Interface + "...")
	switch t.Type {
	case "XFRM":
		sys.Run("swanctl", "--load-all")
		if err := sys.Run("ifup", t.Interface); err != nil {
			uiOut.Warn("ifup failed (maybe already up?)")
		}
	case "WireGuard":
		if err := sys.Run("wg-quick", "up", t.Interface); err != nil {
			uiOut.Warn("wg-quick up failed")
		}
	case "AmneziaWG":
		if err := sys.Run("awg-quick", "up", t.Interface); err != nil {
			uiOut.Warn("awg-quick up failed")
		}
	case "StaticXFRM", "VXLAN", "GRE":
		if err := sys.Run("ifup", t.Interface); err != nil {
			uiOut.Warn("ifup failed")
		}
	}
	uiOut.Ok("Done")
}

func bringTunnelDown(uiOut *ui.UI, t ManagedTunnel) {
	uiOut.Info("Bringing down " + t.Interface + "...")
	switch t.Type {
	case "XFRM":
		if err := sys.Run("ifdown", t.Interface); err != nil {
			uiOut.Warn("ifdown failed")
		}
	case "WireGuard":
		if err := sys.Run("wg-quick", "down", t.Interface); err != nil {
			uiOut.Warn("wg-quick down failed")
		}
	case "AmneziaWG":
		if err := sys.Run("awg-quick", "down", t.Interface); err != nil {
			uiOut.Warn("awg-quick down failed")
		}
	case "StaticXFRM", "VXLAN", "GRE":
		if err := sys.Run("ifdown", t.Interface); err != nil {
			uiOut.Warn("ifdown failed")
		}
	}
	uiOut.Ok("Done")
}

func editTunnelConfig(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		if sys.LookPath("nano") {
			editor = "nano"
		} else if sys.LookPath("vi") {
			editor = "vi"
		} else {
			return errors.New("no editor found (nano/vi), please set EDITOR env var")
		}
	}

	fileToEdit := t.MainConfig
	if len(t.ExtraFiles) > 0 {
		var existing []string
		for _, f := range append([]string{t.MainConfig}, t.ExtraFiles...) {
			if fileExists(f) {
				existing = append(existing, f)
			}
		}

		if len(existing) > 1 {
			opts := make([]ui.Option, len(existing))
			for i, f := range existing {
				opts[i] = ui.Option{Label: f, Value: f}
			}
			if err := askSelectRaw(prompter, "Select file to edit", opts, &fileToEdit); err != nil {
				return err
			}
		}
	}

	if !fileExists(fileToEdit) {
		return fmt.Errorf("file does not exist: %s", fileToEdit)
	}

	uiOut.Info("Opening " + fileToEdit + " in " + editor + "...")
	return sys.Run(editor, fileToEdit)
}

func deleteTunnel(uiOut *ui.UI, t ManagedTunnel) {
	uiOut.Info("Deleting " + t.Interface + "...")

	// Disable systemd service if applicable
	switch t.Type {
	case "WireGuard":
		sys.Run("systemctl", "disable", "--now", "wg-quick@"+t.Interface)
	case "AmneziaWG":
		sys.Run("systemctl", "disable", "--now", "awg-quick@"+t.Interface)
	}

	// Bring down first to be safe
	bringTunnelDown(uiOut, t)

	// Force link deletion just in case
	sys.Output("ip", "link", "del", t.Interface)

	// Remove files
	files := append([]string{t.MainConfig}, t.ExtraFiles...)

	// If XFRM, also try to clean up RPK keys
	if t.Type == "XFRM" {
		swanctlDir := "/etc/swanctl"
		prefix := t.Name // e.g. "prod1"
		files = append(files,
			filepath.Join(swanctlDir, "ecdsa", prefix+"-local.key"),
			filepath.Join(swanctlDir, "pubkey", prefix+"-local.pub"),
			filepath.Join(swanctlDir, "pubkey", prefix+"-remote.pub"),
		)
	}

	for _, f := range files {
		if fileExists(f) {
			if err := os.Remove(f); err != nil {
				uiOut.Warn("Failed to delete " + f + ": " + err.Error())
			} else {
				uiOut.Ok("Deleted " + f)
			}
		}
	}

	if t.Type == "XFRM" {
		uiOut.Info("Reloading swanctl config...")
		sys.Run("swanctl", "--load-all")
	}

	uiOut.Ok("Tunnel deleted completely.")
}
