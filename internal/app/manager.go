package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	tunnels, err := scanTunnels(xfrmConfDir)
	if err != nil {
		return err
	}

	if len(tunnels) == 0 {
		uiOut.Warn("No tunnels found.")
		uiOut.Dim("\nPress Enter to return to main menu...")
		_, _ = uiOut.ReadLine()
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
			if err := structuredEditTunnel(uiOut, prompter, t); err != nil {
				if err != ErrAborted {
					uiOut.Warn(err.Error())
				}
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

	// OpenVPN
	ovpnDirs := []string{"/etc/openvpn/server", "/etc/openvpn/client"}
	for _, dir := range ovpnDirs {
		files, _ = filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, f := range files {
			base := filepath.Base(f)
			name := strings.TrimSuffix(base, ".conf")

			// Parse config to extract actual interface name
			content, _ := os.ReadFile(f)
			iface := ""
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "dev ") {
					iface = strings.TrimSpace(strings.TrimPrefix(line, "dev "))
					break
				}
			}
			if iface == "" {
				iface = "tun-" + name
			}

			var extraFiles []string
			for _, ext := range []string{".crt", ".key"} {
				extraPath := filepath.Join(dir, name+ext)
				if fileExists(extraPath) {
					extraFiles = append(extraFiles, extraPath)
				}
			}

			role := "server"
			if strings.Contains(dir, "client") {
				role = "client"
			}

			t := ManagedTunnel{
				Type:       "OpenVPN (" + role + ")",
				Name:       name,
				Interface:  iface,
				MainConfig: f,
				ExtraFiles: extraFiles,
			}
			tunnels = append(tunnels, t)
		}
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

	// SRv6
	if fileExists(SRv6ConfigFile) {
		t := ManagedTunnel{
			Type:       "SRv6",
			Name:       "srv6-tunnel",
			Interface:  "",
			MainConfig: SRv6ConfigFile,
		}
		tunnels = append(tunnels, t)
	}

	return tunnels, nil
}

func showTunnelStatus(uiOut *ui.UI, t ManagedTunnel) {
	if t.Type != "SRv6" {
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
	case "OpenVPN (server)", "OpenVPN (client)":
		role := "server"
		if strings.Contains(t.Type, "client") {
			role = "client"
		}
		serviceName := fmt.Sprintf("openvpn-%s@%s", role, t.Name)
		uiOut.Info(fmt.Sprintf("systemctl status %s:", serviceName))
		out, _ = sys.Output("systemctl", "status", "--no-pager", serviceName)
		fmt.Fprintln(uiOut.Out, out)
	case "SRv6":
		var config SRv6Config
		if b, err := os.ReadFile(t.MainConfig); err == nil {
			json.Unmarshal(b, &config)
			showSRv6Status(uiOut, config)
		}
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
	case "OpenVPN (server)", "OpenVPN (client)":
		role := "server"
		if strings.Contains(t.Type, "client") {
			role = "client"
		}
		serviceName := fmt.Sprintf("openvpn-%s@%s", role, t.Name)
		if err := sys.Run("systemctl", "start", serviceName); err != nil {
			uiOut.Warn(fmt.Sprintf("failed to start %s", serviceName))
		}
	case "StaticXFRM", "VXLAN", "GRE":
		if err := sys.Run("ifup", t.Interface); err != nil {
			uiOut.Warn("ifup failed")
		}
	case "SRv6":
		var config SRv6Config
		if b, err := os.ReadFile(t.MainConfig); err == nil {
			json.Unmarshal(b, &config)
			applySRv6(uiOut, config)
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
	case "OpenVPN (server)", "OpenVPN (client)":
		role := "server"
		if strings.Contains(t.Type, "client") {
			role = "client"
		}
		serviceName := fmt.Sprintf("openvpn-%s@%s", role, t.Name)
		if err := sys.Run("systemctl", "stop", serviceName); err != nil {
			uiOut.Warn(fmt.Sprintf("failed to stop %s", serviceName))
		}
	case "StaticXFRM", "VXLAN", "GRE":
		if err := sys.Run("ifdown", t.Interface); err != nil {
			uiOut.Warn("ifdown failed")
		}
	}
	uiOut.Ok("Done")
}

func structuredEditTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	options := []ui.Option{
		{Label: "1) Interactive Edit (Change Fields)", Value: "interactive"},
		{Label: "2) Manual Edit (Open in Editor)", Value: "manual"},
		{Label: "0) Back", Value: "back"},
	}

	choice := "interactive"
	if err := askSelectRaw(prompter, "Edit Mode", options, &choice); err != nil {
		return err
	}

	if choice == "back" {
		return nil
	}

	if choice == "manual" {
		return editTunnelConfig(uiOut, prompter, t)
	}

	// Interactive edit
	var err error
	switch t.Type {
	case "WireGuard", "AmneziaWG":
		err = editWgLikeTunnel(uiOut, prompter, t)
	case "VXLAN", "GRE", "StaticXFRM":
		err = editIfupdownTunnel(uiOut, prompter, t)
	case "XFRM":
		err = editXfrmTunnel(uiOut, prompter, t)
	case "OpenVPN (server)", "OpenVPN (client)":
		err = editOpenVPNTunnel(uiOut, prompter, t)
	case "SRv6":
		var config SRv6Config
		if b, err := os.ReadFile(t.MainConfig); err == nil {
			if err := json.Unmarshal(b, &config); err != nil {
				return err
			}
			err = editSRv6(uiOut, prompter, &config)
		} else {
			err = err
		}
	default:
		uiOut.Warn("Interactive edit not supported for " + t.Type)
		return editTunnelConfig(uiOut, prompter, t)
	}

	if err != nil {
		return err
	}

	// Restart interface if changed, except for SRv6 which handles its own updates
	if t.Type != "SRv6" {
		ok, err := askConfirm(prompter, "Configuration updated. Restart interface now?", true)
		if err != nil {
			return err
		}
		if ok {
			bringTunnelDown(uiOut, t)
			bringTunnelUp(uiOut, t)
		}
	}

	return nil
}

func editWgLikeTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	content, err := os.ReadFile(t.MainConfig)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")

	fields := []struct {
		Label string
		Key   string
		Value string
	}{
		{"Address", "Address", ""},
		{"ListenPort", "ListenPort", ""},
		{"MTU", "MTU", ""},
		{"Endpoint", "Endpoint", ""},
		{"PersistentKeepalive", "PersistentKeepalive", ""},
		{"PublicKey (Remote)", "PublicKey", ""},
	}

	// 如果是 AmneziaWG，增加混淆参数
	if t.Type == "AmneziaWG" {
		fields = append(fields,
			struct{ Label, Key, Value string }{"Jc (Junk Packets)", "Jc", ""},
			struct{ Label, Key, Value string }{"Jmin", "Jmin", ""},
			struct{ Label, Key, Value string }{"Jmax", "Jmax", ""},
			struct{ Label, Key, Value string }{"S1 (Init Padding)", "S1", ""},
			struct{ Label, Key, Value string }{"S2 (Resp Padding)", "S2", ""},
			struct{ Label, Key, Value string }{"H1 (Header)", "H1", ""},
			struct{ Label, Key, Value string }{"H2", "H2", ""},
			struct{ Label, Key, Value string }{"H3", "H3", ""},
			struct{ Label, Key, Value string }{"H4", "H4", ""},
		)
	}

	// Basic parser
	for i, f := range fields {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(f.Key)) && strings.Contains(trimmed, "=") {
				parts := strings.SplitN(trimmed, "=", 2)
				fields[i].Value = strings.TrimSpace(parts[1])
			}
		}
	}

	opts := make([]ui.Option, len(fields)+2)
	opts[0] = ui.Option{Label: ">> Save Changes and Exit", Value: "save"}
	opts[1] = ui.Option{Label: "!! Discard Changes and Back", Value: "discard"}
	for i, f := range fields {
		opts[i+2] = ui.Option{Label: fmt.Sprintf("%s: %s", f.Label, f.Value), Value: fmt.Sprintf("%d", i)}
	}

	for {
		choice := ""
		if err := askSelectRaw(prompter, "Interactive Editor (Select field to modify)", opts, &choice); err != nil {
			return err
		}

		if choice == "save" {
			break
		}
		if choice == "discard" {
			return ErrAborted
		}

		idx := 0
		fmt.Sscanf(choice, "%d", &idx)
		f := &fields[idx]

		newVal := f.Value
		if err := askInput(prompter, "Enter new value for "+f.Label, &newVal, nil); err != nil {
			return err
		}
		f.Value = strings.TrimSpace(newVal)
		opts[idx].Label = fmt.Sprintf("%s: %s", f.Label, f.Value)
	}

	// Reconstruct or update
	var resultLines []string
	updatedKeys := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			key := strings.TrimSpace(parts[0])

			foundField := -1
			for i, f := range fields {
				if strings.EqualFold(key, f.Key) {
					foundField = i
					break
				}
			}

			if foundField >= 0 {
				f := fields[foundField]
				updatedKeys[f.Key] = true
				if f.Value != "" {
					indent := ""
					if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
						indent = line[:len(line)-len(strings.TrimLeft(line, " \t"))]
					}
					resultLines = append(resultLines, fmt.Sprintf("%s%s = %s", indent, key, f.Value))
				}
				// If f.Value is empty, we skip this line (effectively deleting it)
				continue
			}
		}
		resultLines = append(resultLines, line)
	}

	// Add missing keys that have values
	for _, f := range fields {
		if f.Value != "" && !updatedKeys[f.Key] {
			// Add to appropriate section
			section := "[Interface]"
			if f.Key == "Endpoint" || f.Key == "PersistentKeepalive" || f.Key == "PublicKey" {
				section = "[Peer]"
			}

			newResult := make([]string, 0, len(resultLines)+1)
			added := false
			for _, line := range resultLines {
				newResult = append(newResult, line)
				if strings.TrimSpace(line) == section && !added {
					newResult = append(newResult, fmt.Sprintf("%s = %s", f.Key, f.Value))
					added = true
				}
			}
			if !added {
				newResult = append(newResult, section, fmt.Sprintf("%s = %s", f.Key, f.Value))
			}
			resultLines = newResult
		}
	}

	// Post-processing: No Endpoint -> No Keepalive (Extra safety)
	hasEndpoint := false
	for _, f := range fields {
		if f.Key == "Endpoint" && f.Value != "" {
			hasEndpoint = true
			break
		}
	}

	var finalLines []string
	for _, line := range resultLines {
		if !hasEndpoint && strings.Contains(strings.ToLower(line), "persistentkeepalive") {
			continue
		}
		finalLines = append(finalLines, line)
	}

	return os.WriteFile(t.MainConfig, []byte(strings.Join(finalLines, "\n")), 0600)
}

func editIfupdownTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	content, err := os.ReadFile(t.MainConfig)
	if err != nil {
		return err
	}
	text := string(content)

	type field struct {
		Label string
		Regex *regexp.Regexp
		Value string
		Key   string // 严格锁定的关键字前缀
	}

	// 锁定前缀，防止误匹配（例如防止 id 匹配到 if_id）
	fields := []field{
		{"Local Underlay", regexp.MustCompile(`\s+local\s+([^\s]+)`), "", "local"},
		{"Remote Underlay", regexp.MustCompile(`\s+remote\s+([^\s]+)`), "", "remote"},
		{"Inner CIDR", regexp.MustCompile(`replace\s+([^\s/]+/[0-9]+)`), "", "replace"},
		{"MTU", regexp.MustCompile(`\s+mtu\s+([0-9]+)`), "", "mtu"},
	}

	if t.Type == "VXLAN" {
		// 使用 \s+id\s+ 确保精准锁定 VXLAN ID，不被 if_id 干扰
		fields = append(fields, field{"VNI", regexp.MustCompile(`\s+id\s+([0-9]+)`), "", "id"})
	}

	if t.Type == "StaticXFRM" {
		fields = append(fields,
			field{"SPI In", regexp.MustCompile(`spi\s+(0x[0-9a-fA-F]+)`), "", "spi"},
			field{"SPI Out", regexp.MustCompile(`spi\s+(0x[0-9a-fA-F]+)`), "", "spi"},
			field{"Enc Key In", regexp.MustCompile(`0x([0-9a-fA-F]{32,})`), "", "0x"},
			field{"Enc Key Out", regexp.MustCompile(`0x([0-9a-fA-F]{32,})`), "", "0x"},
		)
	}

	// 提取逻辑：按行处理，跳过注释
	lines := strings.Split(text, "\n")
	for i, f := range fields {
		matchCount := 0
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			m := f.Regex.FindStringSubmatch(line)
			if len(m) > 1 {
				matchCount++
				// 对于 In/Out 方向，根据出现顺序锁定
				if strings.Contains(f.Label, "Out") {
					if matchCount == 2 {
						fields[i].Value = m[1]
						break
					}
				} else {
					fields[i].Value = m[1]
					if !strings.Contains(f.Label, "In") {
						break
					}
				}
			}
		}
	}

	opts := make([]ui.Option, len(fields)+2)
	opts[0] = ui.Option{Label: ">> Save Changes and Exit", Value: "save"}
	opts[1] = ui.Option{Label: "!! Discard Changes and Back", Value: "discard"}
	for i, f := range fields {
		opts[i+2] = ui.Option{Label: fmt.Sprintf("%s: %s", f.Label, f.Value), Value: fmt.Sprintf("%d", i)}
	}

	for {
		choice := ""
		if err := askSelectRaw(prompter, "Interactive Editor (Select field to modify)", opts, &choice); err != nil {
			return err
		}
		if choice == "save" {
			break
		}
		if choice == "discard" {
			return ErrAborted
		}
		idx := 0
		fmt.Sscanf(choice, "%d", &idx)
		f := &fields[idx]
		newVal := f.Value
		if err := askInput(prompter, "Enter new value for "+f.Label, &newVal, nil); err != nil {
			return err
		}

		f.Value = strings.TrimSpace(newVal)
		opts[idx+2].Label = fmt.Sprintf("%s: %s", f.Label, f.Value)
	}

	// 统一在最后执行替换逻辑
	for _, f := range fields {
		// 寻找该字段在 text 中的原始值并替换（这里需要根据 Regex 找到当前值）
		// 为了简单且鲁棒，我们重新解析 text
		m := f.Regex.FindStringSubmatch(text)
		if len(m) > 1 {
			oldInFile := m[1]
			if oldInFile == f.Value {
				continue
			}
			// 执行替换
			if f.Key != "" && f.Key != "0x" {
				pattern := regexp.MustCompile(`(` + regexp.QuoteMeta(f.Key) + `\s+)` + regexp.QuoteMeta(oldInFile))
				text = pattern.ReplaceAllString(text, `${1}`+f.Value)
			} else {
				text = strings.ReplaceAll(text, oldInFile, f.Value)
			}
		}
	}

	return os.WriteFile(t.MainConfig, []byte(text), 0600)
}

func editXfrmTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	connContent, err := os.ReadFile(t.MainConfig)
	if err != nil {
		return err
	}
	connText := string(connContent)

	fields := []struct {
		Label string
		Regex *regexp.Regexp
		Value string
		File  string
	}{
		{"Local Underlay", regexp.MustCompile(`local_addrs\s*=\s*([^\s\n]+)`), "", t.MainConfig},
		{"Remote Underlay", regexp.MustCompile(`remote_addrs\s*=\s*([^\s\n]+)`), "", t.MainConfig},
		{"Local ID", regexp.MustCompile(`(?s)local\s*\{[^}]*id\s*=\s*([^\s\n"}]+)`), "", t.MainConfig},
		{"Remote ID", regexp.MustCompile(`(?s)remote\s*\{[^}]*id\s*=\s*([^\s\n"}]+)`), "", t.MainConfig},
	}

	for i, f := range fields {
		m := f.Regex.FindStringSubmatch(connText)
		if len(m) > 1 {
			fields[i].Value = strings.Trim(m[1], " \"\t\r")
		}
	}

	// Add Inner CIDR from .cfg file
	var cfgFile string
	for _, f := range t.ExtraFiles {
		if strings.HasSuffix(f, ".cfg") {
			cfgFile = f
			break
		}
	}

	if cfgFile != "" {
		cfgContent, _ := os.ReadFile(cfgFile)
		cfgText := string(cfgContent)
		m := regexp.MustCompile(`replace\s+([^\s/]+/[0-9]+)`).FindStringSubmatch(cfgText)
		val := ""
		if len(m) > 1 {
			val = m[1]
		}
		fields = append(fields, struct {
			Label string
			Regex *regexp.Regexp
			Value string
			File  string
		}{"Inner CIDR", regexp.MustCompile(`replace\s+([^\s/]+/[0-9]+)`), val, cfgFile})
	}

	opts := make([]ui.Option, len(fields)+2)
	opts[0] = ui.Option{Label: ">> Save Changes and Exit", Value: "save"}
	opts[1] = ui.Option{Label: "!! Discard Changes and Back", Value: "discard"}
	for i, f := range fields {
		opts[i+2] = ui.Option{Label: fmt.Sprintf("%s: %s", f.Label, f.Value), Value: fmt.Sprintf("%d", i)}
	}

	for {
		choice := ""
		if err := askSelectRaw(prompter, "Interactive Editor (Select field to modify)", opts, &choice); err != nil {
			return err
		}
		if choice == "save" {
			break
		}
		if choice == "discard" {
			return ErrAborted
		}
		idx := 0
		fmt.Sscanf(choice, "%d", &idx)
		f := &fields[idx]
		newVal := f.Value
		if err := askInput(prompter, "Enter new value for "+f.Label, &newVal, nil); err != nil {
			return err
		}
		f.Value = strings.TrimSpace(newVal)
		opts[idx+2].Label = fmt.Sprintf("%s: %s", f.Label, f.Value)
	}

	// 执行最后的保存逻辑
	for _, f := range fields {
		if f.File == t.MainConfig {
			m := f.Regex.FindStringSubmatchIndex(connText)
			if len(m) > 1 {
				currentVal := connText[m[2]:m[3]]
				if currentVal != f.Value {
					connText = connText[:m[2]] + f.Value + connText[m[3]:]
				}
			}
		} else {
			// Update .cfg file
			cfgContent, _ := os.ReadFile(f.File)
			cfgText := string(cfgContent)
			m := f.Regex.FindStringSubmatchIndex(cfgText)
			if len(m) > 1 {
				currentVal := cfgText[m[2]:m[3]]
				if currentVal != f.Value {
					cfgText = cfgText[:m[2]] + f.Value + cfgText[m[3]:]
					os.WriteFile(f.File, []byte(cfgText), 0600)
				}
			}
		}
	}

	return os.WriteFile(t.MainConfig, []byte(connText), 0600)
}

func editOpenVPNTunnel(uiOut *ui.UI, prompter *ui.Prompter, t ManagedTunnel) error {
	content, err := os.ReadFile(t.MainConfig)
	if err != nil {
		return err
	}
	text := string(content)

	fields := []struct {
		Label string
		Regex *regexp.Regexp
		Value string
		Key   string
	}{
		{"Local Listen IP", regexp.MustCompile(`^local\s+([^\s]+)`), "", "local"},
		{"Remote Underlay IP", regexp.MustCompile(`^remote\s+([^\s]+)`), "", "remote"},
		{"Port", regexp.MustCompile(`^port\s+([0-9]+)`), "", "port"},
		{"MTU", regexp.MustCompile(`^tun-mtu\s+([0-9]+)`), "", "tun-mtu"},
		{"Inner IP", regexp.MustCompile(`ip addr add\s+([^\s]+)`), "", "inner"},
		{"Peer Fingerprint", regexp.MustCompile(`^peer-fingerprint\s+"?([^"\n]+)"?`), "", "peer-fingerprint"},
	}

	lines := strings.Split(text, "\n")
	for i, f := range fields {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || (strings.HasPrefix(trimmed, "#") && f.Key != "peer-fingerprint") {
				continue
			}
			m := f.Regex.FindStringSubmatch(trimmed)
			if len(m) > 1 {
				fields[i].Value = m[1]
				break
			}
		}
	}

	opts := make([]ui.Option, len(fields)+2)
	opts[0] = ui.Option{Label: ">> Save Changes and Exit", Value: "save"}
	opts[1] = ui.Option{Label: "!! Discard Changes and Back", Value: "discard"}
	for i, f := range fields {
		opts[i+2] = ui.Option{Label: fmt.Sprintf("%s: %s", f.Label, f.Value), Value: fmt.Sprintf("%d", i)}
	}

	for {
		choice := ""
		if err := askSelectRaw(prompter, "Interactive Editor (Select field to modify)", opts, &choice); err != nil {
			return err
		}
		if choice == "save" {
			break
		}
		if choice == "discard" {
			return ErrAborted
		}
		idx := 0
		fmt.Sscanf(choice, "%d", &idx)
		f := &fields[idx]
		newVal := f.Value
		if err := askInput(prompter, "Enter new value for "+f.Label, &newVal, nil); err != nil {
			return err
		}

		f.Value = strings.TrimSpace(newVal)
		opts[idx+2].Label = fmt.Sprintf("%s: %s", f.Label, f.Value)
	}

	var newLines []string
	updatedFields := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			newLines = append(newLines, line)
			continue
		}

		replaced := false
		for _, f := range fields {
			if f.Value == "" {
				continue
			}
			if f.Key == "peer-fingerprint" && strings.Contains(trimmed, "peer-fingerprint") {
				newLines = append(newLines, fmt.Sprintf("%s \"%s\"", f.Key, f.Value))
				updatedFields[f.Key] = true
				replaced = true
				break
			}
			if f.Regex.MatchString(trimmed) {
				if f.Key == "inner" {
					// Handle special case for 'up' script line
					newLine := f.Regex.ReplaceAllString(line, "ip addr add "+f.Value)
					newLines = append(newLines, newLine)
				} else if f.Key == "peer-fingerprint" {
					newLines = append(newLines, fmt.Sprintf("%s \"%s\"", f.Key, f.Value))
				} else {
					newLines = append(newLines, fmt.Sprintf("%s %s", f.Key, f.Value))
				}
				updatedFields[f.Key] = true
				replaced = true
				break
			}
		}

		if !replaced {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(t.MainConfig, []byte(strings.Join(newLines, "\n")), 0600)
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
	case "OpenVPN (server)", "OpenVPN (client)":
		role := "server"
		if strings.Contains(t.Type, "client") {
			role = "client"
		}
		sys.Run("systemctl", "disable", "--now", fmt.Sprintf("openvpn-%s@%s", role, t.Name))
	case "SRv6":
		sys.Run("systemctl", "disable", "--now", "srv6-tunnels.service")
		os.Remove(SRv6Service)
		os.RemoveAll(SRv6WorkDir)
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
