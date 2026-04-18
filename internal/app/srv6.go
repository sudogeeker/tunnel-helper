package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type CarrierConfig struct {
	Name   string `json:"name"`
	SIDV4  string `json:"sid_v4"`
	SIDV6  string `json:"sid_v6"`
	MTU    int    `json:"mtu"`
}

type SRv6Config struct {
	BaseURL  string          `json:"base_url"`
	Iface    string          `json:"iface"`
	TableID  int             `json:"table_id"`
	Carriers []CarrierConfig `json:"carriers"`
}

const (
	SRv6WorkDir    = "/etc/srv6_tunnels"
	SRv6ConfigFile = "/etc/srv6_tunnels/config.json"
	SRv6Service    = "/etc/systemd/system/srv6-tunnels.service"
)

func runSRv6(uiOut *ui.UI, prompter *ui.Prompter) error {
	defIface := defaultDev(6)
	if defIface == "" {
		defIface = defaultDev(4)
	}
	if defIface == "" {
		defIface = "eth0"
	}

	config := SRv6Config{
		BaseURL: "https://cira.moedove.com",
		Iface:   defIface,
		TableID: 100,
		Carriers: []CarrierConfig{
			{"chinamobile", "", "", 1500},
			{"chinaunicom", "", "", 1500},
			{"chinatelecom", "", "", 1500},
			{"cernet_edu", "", "", 1500},
		},
	}

	// Load existing if exists
	if b, err := os.ReadFile(SRv6ConfigFile); err == nil {
		if err := json.Unmarshal(b, &config); err == nil {
			return editSRv6(uiOut, prompter, &config)
		}
	}

	// 1. Base URL
	if err := askInput(prompter, "Base URL for routing files", &config.BaseURL, nil); err != nil {
		return err
	}

	// 2. Interface
	if err := askInput(prompter, fmt.Sprintf("Outbound interface (default %s)", defIface), &config.Iface, validateDeviceName); err != nil {
		return err
	}

	// 2.5. Table ID
	tidStr := fmt.Sprintf("%d", config.TableID)
	if err := askInput(prompter, "Routing Table ID for SRv6 (e.g., 100)", &tidStr, validateNumber); err != nil {
		return err
	}
	fmt.Sscanf(tidStr, "%d", &config.TableID)
	if config.TableID == 0 {
		config.TableID = 100
	}

	// 3. Carriers
	for i := range config.Carriers {
		c := &config.Carriers[i]
		uiOut.Info(fmt.Sprintf("Configuring carrier: %s", c.Name))
		if err := askInput(prompter, "SID for IPv4", &c.SIDV4, nil); err != nil {
			return err
		}
		if err := askInput(prompter, "SID for IPv6", &c.SIDV6, nil); err != nil {
			return err
		}
		mtuStr := fmt.Sprintf("%d", c.MTU)
		if err := askInput(prompter, "MTU", &mtuStr, validateMTU); err != nil {
			return err
		}
		fmt.Sscanf(mtuStr, "%d", &c.MTU)
	}

	// Save config
	if err := saveSRv6Config(uiOut, config); err != nil {
		return err
	}

	// Fetch and Apply
	if err := applySRv6(uiOut, &config); err != nil {
		uiOut.Warn("Initial apply failed: " + err.Error())
	}

	// Setup Systemd Service for Boot
	ok, err := askConfirm(prompter, "Create systemd service for SRv6 tunnel on boot?", true)
	if err != nil {
		return err
	}
	if ok {
		if err := setupSRv6Service(); err != nil {
			return err
		}
		uiOut.Ok("Systemd service created and enabled.")
	}

	return nil
}

func applySRv6(uiOut *ui.UI, config *SRv6Config) error {
	uiOut.Info("Syncing tunnel files and applying SRv6 tunnel...")
	
	// Validate interface exists, fallback to default if not
	if _, err := sys.Output("ip", "link", "show", "dev", config.Iface); err != nil {
		uiOut.Warn(fmt.Sprintf("Interface %s not found, attempting to auto-detect...", config.Iface))
		defIface := defaultDev(6)
		if defIface == "" {
			defIface = defaultDev(4)
		}
		if defIface == "" {
			return fmt.Errorf("failed to detect default interface to replace %s", config.Iface)
		}
		uiOut.Info(fmt.Sprintf("Auto-detected interface: %s", defIface))
		config.Iface = defIface
		
		// Attempt to save the corrected interface back to config
		saveSRv6Config(uiOut, *config)
	}

	tmpDir, err := os.MkdirTemp("", "srv6_routes_*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	gw := getIPv6DefaultGateway(config.Iface)
	gwStr := gw
	if gwStr == "" {
		gwStr = "(none)"
	}
	uiOut.Dim(fmt.Sprintf("Learned IPv6 default gateway for %s: %s", config.Iface, gwStr))
	
	tid := config.TableID
	if tid == 0 {
		tid = 100
	}
	tableStr := fmt.Sprintf("%d", tid)

	uiOut.Dim(fmt.Sprintf("Flushing and preparing routing table %s...", tableStr))
	if out, err := sys.Output("ip", "-6", "route", "flush", "table", tableStr); err != nil {
		if !strings.Contains(out, "FIB table does not exist") && !strings.Contains(err.Error(), "FIB table does not exist") {
			uiOut.Warn(fmt.Sprintf("Warning: flush table %s failed: %v %s", tableStr, err, out))
		}
	}
	
	// Add generic rule for the table if it doesn't exist
	// Use priority 30000 as recommended
	uiOut.Dim(fmt.Sprintf("Adding generic routing rule for table %s...", tableStr))
	for i := 0; i < 10; i++ {
		sys.Output("ip", "-6", "rule", "del", "priority", "30000", "table", tableStr)
	}
	if out, err := sys.Output("ip", "-6", "rule", "add", "priority", "30000", "table", tableStr); err != nil {
		uiOut.Warn(fmt.Sprintf("Failed to add generic routing rule: %v (%s)", err, out))
	}

	// Collect unique SIDs to avoid redundant rule operations
	uniqueSIDs := make(map[string]bool)
	for _, c := range config.Carriers {
		if c.SIDV4 != "" && c.SIDV4 != "::" {
			uniqueSIDs[c.SIDV4] = true
		}
		if c.SIDV6 != "" && c.SIDV6 != "::" {
			uniqueSIDs[c.SIDV6] = true
		}
	}

	for sid := range uniqueSIDs {
		uiOut.Dim(fmt.Sprintf("Setting up privileged routing for SID: %s", sid))
		// Delete all existing rules for this SID and table to prevent duplicates
		// Limit to 100 iterations as a safety break
		for i := 0; i < 100; i++ {
			if _, err := sys.Output("ip", "-6", "rule", "del", "to", sid, "table", tableStr); err != nil {
				break
			}
		}
		// Use priority 100 to ensure it's "privileged" and evaluated before main table
		if out, err := sys.Output("ip", "-6", "rule", "add", "to", sid, "table", tableStr, "priority", "100"); err != nil {
			uiOut.Warn(fmt.Sprintf("Failed to add routing rule for SID %s: %v (%s)", sid, err, out))
		}

		// Forcibly add a direct route for the SID into the privileged table to prevent loops
		var sidRouteArgs []string
		if gw != "" {
			sidRouteArgs = []string{"-6", "route", "replace", sid, "via", gw, "dev", config.Iface, "table", tableStr, "onlink"}
		} else {
			sidRouteArgs = []string{"-6", "route", "replace", sid, "dev", config.Iface, "table", tableStr}
		}
		uiOut.Dim(fmt.Sprintf("Adding direct route for SID %s in table %s...", sid, tableStr))
		if out, err := sys.Output("ip", sidRouteArgs...); err != nil {
			uiOut.Warn(fmt.Sprintf("Failed to add direct route for SID %s in table %s: %v (%s)", sid, tableStr, err, out))
		}
	}

	for _, c := range config.Carriers {
		for _, ver := range []int{4, 6} {
			sid := c.SIDV4
			if ver == 6 {
				sid = c.SIDV6
			}
			if sid == "::" || sid == "" {
				continue
			}

			fileName := fmt.Sprintf("%s_v%d.txt", c.Name, ver)
			localPath := filepath.Join(SRv6WorkDir, fileName)
			url := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.BaseURL, "/"), fileName)

			// Download
			uiOut.Dim(fmt.Sprintf("Processing %s...", fileName))
			resp, err := http.Get(url)
			if err != nil {
				uiOut.Warn(fmt.Sprintf("Failed to download %s: %v. Using cache if available.", fileName, err))
			} else {
				if resp.StatusCode == http.StatusOK {
					f, err := os.Create(localPath)
					if err == nil {
						_, copyErr := io.Copy(f, resp.Body)
						f.Close()
						if copyErr != nil {
							uiOut.Warn(fmt.Sprintf("Failed to save %s: %v", fileName, copyErr))
						}
					} else {
						uiOut.Warn(fmt.Sprintf("Failed to create file %s: %v", localPath, err))
					}
				} else {
					uiOut.Warn(fmt.Sprintf("Failed to download %s (Status %d). Using cache.", fileName, resp.StatusCode))
				}
				resp.Body.Close()
			}

			// Apply
			if !fileExists(localPath) {
				uiOut.Warn(fmt.Sprintf("File %s not found, skipping.", localPath))
				continue
			}

			batchFile := filepath.Join(tmpDir, "batch_"+fileName)
			if err := generateBatchFile(localPath, batchFile, config.Iface, sid, tableStr, c.MTU); err != nil {
				uiOut.Warn(fmt.Sprintf("Failed to generate batch file for %s: %v", fileName, err))
				continue
			}

			if info, err := os.Stat(batchFile); err == nil && info.Size() > 0 {
				verStr := fmt.Sprintf("-%d", ver)
				uiOut.Dim(fmt.Sprintf("Applying routes from %s using ip %s -batch...", fileName, verStr))
				
				maxRetries := 3
				for attempt := 0; attempt <= maxRetries; attempt++ {
					out, err := sys.Output("ip", verStr, "-batch", batchFile)
					if err == nil {
						break
					}
					
					if strings.Contains(out, "Cannot allocate memory") || strings.Contains(err.Error(), "Cannot allocate memory") {
						if attempt < maxRetries {
							uiOut.Warn(fmt.Sprintf("Memory allocation failed when applying %s, retrying (%d/%d)...", fileName, attempt+1, maxRetries))
							time.Sleep(2 * time.Second)
							continue
						} else {
							return fmt.Errorf("failed to apply routes for %s after %d retries: Cannot allocate memory\n%s", fileName, maxRetries, out)
						}
					}
					
					uiOut.Warn(fmt.Sprintf("Failed to apply routes for %s: %v (%s)", fileName, err, out))
					break
				}
			}
		}
	}

	uiOut.Ok("SRv6 tunnel applied successfully.")
	return nil
}

func generateBatchFile(src, dst, iface, sid, table string, mtu int) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// route replace <CIDR> dev <IFACE> encap seg6 mode encap segs <SID> mtu <MTU> table <TABLE>
		fmt.Fprintf(out, "route replace %s dev %s encap seg6 mode encap segs %s mtu %d table %s\n", line, iface, sid, mtu, table)
	}
	return scanner.Err()
}

func setupSRv6Service() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	content := fmt.Sprintf(`[Unit]
Description=SRv6 Tunnel Updater
After=network.target

[Service]
Type=oneshot
ExecStart=%s --srv6-apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, exe)

	if err := os.WriteFile(SRv6Service, []byte(content), 0644); err != nil {
		return err
	}

	sys.Run("systemctl", "daemon-reload")
	return sys.Run("systemctl", "enable", "srv6-tunnels.service")
}

func removeSRv6Service() error {
	sys.Run("systemctl", "disable", "srv6-tunnels.service")
	sys.Run("systemctl", "stop", "srv6-tunnels.service")
	os.Remove(SRv6Service)
	sys.Run("systemctl", "daemon-reload")
	return nil
}

func manageSRv6Service(uiOut *ui.UI, prompter *ui.Prompter) error {
	for {
		uiOut.Info("Systemd Service Status:")
		out, _ := sys.Output("systemctl", "status", "srv6-tunnels.service", "--no-pager")
		if out == "" {
			fmt.Fprintln(uiOut.Out, "Service is not installed or not running.")
		} else {
			fmt.Fprintln(uiOut.Out, out)
		}

		options := []ui.Option{
			{Label: "1) Install/Enable Service", Value: "install"},
			{Label: "2) Uninstall/Disable Service", Value: "uninstall"},
			{Label: "0) Back", Value: "back"},
		}
		
		choice := ""
		if err := askSelectRaw(prompter, "Manage Systemd Service", options, &choice); err != nil {
			return err
		}

		switch choice {
		case "install":
			if err := setupSRv6Service(); err != nil {
				uiOut.Warn(fmt.Sprintf("Failed to install service: %v", err))
			} else {
				uiOut.Ok("Service installed and enabled.")
			}
		case "uninstall":
			if err := removeSRv6Service(); err != nil {
				uiOut.Warn(fmt.Sprintf("Failed to uninstall service: %v", err))
			} else {
				uiOut.Ok("Service uninstalled and disabled.")
			}
		case "back":
			return nil
		}
	}
}

func saveSRv6Config(uiOut *ui.UI, config SRv6Config) error {
	if err := os.MkdirAll(SRv6WorkDir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(SRv6ConfigFile, b, 0644); err != nil {
		return err
	}
	uiOut.Ok("Configuration saved to " + SRv6ConfigFile)
	return nil
}

func editSRv6(uiOut *ui.UI, prompter *ui.Prompter, config *SRv6Config) error {
	initialJSON, _ := json.Marshal(config)

	for {
		tid := config.TableID
		if tid == 0 {
			tid = 100
		}
		options := []ui.Option{
			{Label: "1) View SRv6 Status", Value: "status"},
			{Label: "2) Manage Systemd Service", Value: "service"},
			{Label: "3) Update Tunnel Now", Value: "update"},
			{Label: "-------------------------", Value: "none"},
			{Label: "4) Edit Base URL: " + config.BaseURL, Value: "url"},
			{Label: "5) Edit Interface: " + config.Iface, Value: "iface"},
			{Label: fmt.Sprintf("6) Edit Table ID: %d", tid), Value: "table"},
			{Label: "7) Edit Carriers", Value: "carriers"},
			{Label: "-------------------------", Value: "none"},
			{Label: "8) Delete SRv6 Tunnel", Value: "delete"},
			{Label: "0) Back", Value: "back"},
		}

		choice := ""
		if err := askSelectRaw(prompter, "SRv6 Configuration Menu", options, &choice); err != nil {
			return err
		}

		if choice == "none" {
			continue
		}

		switch choice {
		case "status":
			showSRv6Status(uiOut, *config)
		case "service":
			if err := manageSRv6Service(uiOut, prompter); err != nil {
				return err
			}
		case "update":
			if err := saveSRv6Config(uiOut, *config); err != nil {
				uiOut.Warn("Failed to save config: " + err.Error())
			}
			applySRv6(uiOut, config)
			// Update initialJSON after successful save to mark as clean
			initialJSON, _ = json.Marshal(config)
		case "url":
			askInput(prompter, "Base URL", &config.BaseURL, nil)
		case "iface":
			askInput(prompter, "Interface", &config.Iface, nil)
		case "table":
			tidStr := fmt.Sprintf("%d", tid)
			askInput(prompter, "Routing Table ID", &tidStr, validateNumber)
			fmt.Sscanf(tidStr, "%d", &config.TableID)
			if config.TableID == 0 {
				config.TableID = 100
			}
		case "carriers":
			if err := editCarriers(uiOut, prompter, config); err != nil {
				return err
			}
		case "delete":
			ok, err := askConfirm(prompter, "Delete SRv6 tunnel files and tear down?", false)
			if err != nil {
				return err
			}
			if ok {
				uiOut.Info("Deleting SRv6 Tunnel and cleaning up rules...")
				
				tid := config.TableID
				if tid == 0 {
					tid = 100
				}
				tableStr := fmt.Sprintf("%d", tid)

				// Cleanup rules
				for i := 0; i < 10; i++ {
					sys.Output("ip", "-6", "rule", "del", "priority", "30000", "table", tableStr)
				}
				
				uniqueSIDs := make(map[string]bool)
				for _, c := range config.Carriers {
					if c.SIDV4 != "" && c.SIDV4 != "::" {
						uniqueSIDs[c.SIDV4] = true
					}
					if c.SIDV6 != "" && c.SIDV6 != "::" {
						uniqueSIDs[c.SIDV6] = true
					}
				}
				for sid := range uniqueSIDs {
					for i := 0; i < 100; i++ {
						if _, err := sys.Output("ip", "-6", "rule", "del", "to", sid, "table", tableStr); err != nil {
							break
						}
					}
				}

				// Flush table
				sys.Output("ip", "-6", "route", "flush", "table", tableStr)

				sys.Run("systemctl", "disable", "--now", "srv6-tunnels.service")
				os.Remove(SRv6Service)
				os.RemoveAll(SRv6WorkDir)
				uiOut.Ok("SRv6 tunnel deleted completely.")
				return ErrAborted // returns to the previous menu
			}
		case "back":
			currentJSON, _ := json.Marshal(config)
			if string(initialJSON) != string(currentJSON) {
				options := []ui.Option{
					{Label: "Yes, Save and Back", Value: "save"},
					{Label: "No, Discard and Back", Value: "discard"},
					{Label: "Cancel", Value: "cancel"},
				}
				choice := ""
				if err := askSelectRaw(prompter, "Unsaved changes detected. Save now?", options, &choice); err != nil {
					return err
				}
				if choice == "cancel" {
					continue
				}
				if choice == "save" {
					if err := saveSRv6Config(uiOut, *config); err != nil {
						uiOut.Warn("Failed to save: " + err.Error())
						continue
					}
				}
			}
			return nil
		}
	}
}

func editCarriers(uiOut *ui.UI, prompter *ui.Prompter, config *SRv6Config) error {
	for {
		options := make([]ui.Option, len(config.Carriers)+1)
		for i, c := range config.Carriers {
			options[i] = ui.Option{Label: c.Name, Value: fmt.Sprintf("%d", i)}
		}
		options[len(config.Carriers)] = ui.Option{Label: "Back", Value: "back"}

		choice := ""
		if err := askSelectRaw(prompter, "Select Carrier to Edit", options, &choice); err != nil {
			return err
		}

		if choice == "back" {
			return nil
		}

		idx := 0
		fmt.Sscanf(choice, "%d", &idx)
		c := &config.Carriers[idx]

		for {
			carrierOpts := []ui.Option{
				{Label: "SID V4: " + c.SIDV4, Value: "sid4"},
				{Label: "SID V6: " + c.SIDV6, Value: "sid6"},
				{Label: "MTU:    " + fmt.Sprintf("%d", c.MTU), Value: "mtu"},
				{Label: "Back", Value: "back"},
			}
			field := ""
			if err := askSelectRaw(prompter, "Edit Carrier: "+c.Name, carrierOpts, &field); err != nil {
				return err
			}
			if field == "back" {
				break
			}
			switch field {
			case "sid4":
				askInput(prompter, "SID V4", &c.SIDV4, nil)
			case "sid6":
				askInput(prompter, "SID V6", &c.SIDV6, nil)
			case "mtu":
				mtuStr := fmt.Sprintf("%d", c.MTU)
				askInput(prompter, "MTU", &mtuStr, validateMTU)
				fmt.Sscanf(mtuStr, "%d", &c.MTU)
			}
		}
	}
}

func showSRv6Status(uiOut *ui.UI, config SRv6Config) {
	tid := config.TableID
	if tid == 0 {
		tid = 100
	}
	uiOut.Info(fmt.Sprintf("SRv6 Carriers Status (Table %d):", tid))
	for _, c := range config.Carriers {
		fmt.Fprintf(uiOut.Out, "Carrier: %s\n", c.Name)
		fmt.Fprintf(uiOut.Out, "  SID V4: %s\n", c.SIDV4)
		fmt.Fprintf(uiOut.Out, "  SID V6: %s\n", c.SIDV6)
		fmt.Fprintf(uiOut.Out, "  MTU:    %d\n", c.MTU)
		
		v4File := filepath.Join(SRv6WorkDir, c.Name+"_v4.txt")
		v6File := filepath.Join(SRv6WorkDir, c.Name+"_v6.txt")
		
		if info, err := os.Stat(v4File); err == nil {
			fmt.Fprintf(uiOut.Out, "  V4 File: %s (%s)\n", v4File, info.ModTime().Format(time.RFC3339))
		}
		if info, err := os.Stat(v6File); err == nil {
			fmt.Fprintf(uiOut.Out, "  V6 File: %s (%s)\n", v6File, info.ModTime().Format(time.RFC3339))
		}
	}

	uiOut.Info("Systemd Service Status:")
	out, _ := sys.Output("systemctl", "status", "srv6-tunnels.service", "--no-pager")
	fmt.Fprintln(uiOut.Out, out)
}

func getIPv6DefaultGateway(iface string) string {
	out, err := sys.Output("ip", "-6", "route", "show", "default", "dev", iface)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}
