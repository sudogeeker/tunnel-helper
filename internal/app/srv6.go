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
	Carriers []CarrierConfig `json:"carriers"`
}

const (
	SRv6WorkDir    = "/etc/srv6_tunnels"
	SRv6ConfigFile = "/etc/srv6_tunnels/config.json"
	SRv6Service    = "/etc/systemd/system/srv6-tunnels.service"
)

func runSRv6(uiOut *ui.UI, prompter *ui.Prompter) error {
	config := SRv6Config{
		BaseURL: "https://cira.moedove.com",
		Iface:   "eth0",
		Carriers: []CarrierConfig{
			{"chinamobile", "", "", 1500},
			{"chinaunicom", "", "", 1500},
			{"chinatelecom", "", "", 1500},
			{"cernet_edu", "", "", 1500},
		},
	}

	// Load existing if exists
	if b, err := os.ReadFile(SRv6ConfigFile); err == nil {
		json.Unmarshal(b, &config)
	}

	// 1. Base URL
	if err := askInput(prompter, "Base URL for routing files", &config.BaseURL, nil); err != nil {
		return err
	}

	// 2. Interface
	if err := askInput(prompter, "Outbound interface (e.g., eth0)", &config.Iface, nil); err != nil {
		return err
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
		if err := askInput(prompter, "MTU", &mtuStr, validateNumber); err != nil {
			return err
		}
		fmt.Sscanf(mtuStr, "%d", &c.MTU)
	}

	// Save config
	if err := os.MkdirAll(SRv6WorkDir, 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(SRv6ConfigFile, b, 0644); err != nil {
		return err
	}

	// Fetch and Apply
	if err := applySRv6(uiOut, config); err != nil {
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

func applySRv6(uiOut *ui.UI, config SRv6Config) error {
	uiOut.Info("Syncing tunnel files and applying SRv6 tunnel...")
	
	tmpDir, err := os.MkdirTemp("", "srv6_routes_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

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
			uiOut.Dim(fmt.Sprintf("Downloading %s...", fileName))
			resp, err := http.Get(url)
			if err != nil {
				uiOut.Warn(fmt.Sprintf("Failed to download %s: %v. Using cache if available.", fileName, err))
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					f, _ := os.Create(localPath)
					io.Copy(f, resp.Body)
					f.Close()
				} else {
					uiOut.Warn(fmt.Sprintf("Failed to download %s (Status %d). Using cache.", fileName, resp.StatusCode))
				}
			}

			// Apply
			if !fileExists(localPath) {
				continue
			}

			batchFile := filepath.Join(tmpDir, "batch_"+fileName)
			if err := generateBatchFile(localPath, batchFile, config.Iface, sid, c.MTU); err != nil {
				return err
			}

			if info, err := os.Stat(batchFile); err == nil && info.Size() > 0 {
				verStr := fmt.Sprintf("-%d", ver)
				if _, err := sys.Output("ip", verStr, "-batch", batchFile); err != nil {
					uiOut.Warn(fmt.Sprintf("Failed to apply tunnel for %s: %v", fileName, err))
				}
			}
		}
	}

	uiOut.Ok("SRv6 tunnel applied.")
	return nil
}

func generateBatchFile(src, dst, iface, sid string, mtu int) error {
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
		// route replace <CIDR> dev <IFACE> encap seg6 mode encap segs <SID> mtu <MTU>
		fmt.Fprintf(out, "route replace %s dev %s encap seg6 mode encap segs %s mtu %d\n", line, iface, sid, mtu)
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

func editSRv6(uiOut *ui.UI, prompter *ui.Prompter, config *SRv6Config) error {
	for {
		options := []ui.Option{
			{Label: "1) Base URL: " + config.BaseURL, Value: "url"},
			{Label: "2) Interface: " + config.Iface, Value: "iface"},
			{Label: "3) Edit Carriers", Value: "carriers"},
			{Label: "4) Update Tunnel Now", Value: "update"},
			{Label: "0) Back", Value: "back"},
		}

		choice := ""
		if err := askSelectRaw(prompter, "Edit SRv6 Configuration", options, &choice); err != nil {
			return err
		}

		switch choice {
		case "url":
			askInput(prompter, "Base URL", &config.BaseURL, nil)
		case "iface":
			askInput(prompter, "Interface", &config.Iface, nil)
		case "carriers":
			if err := editCarriers(uiOut, prompter, config); err != nil {
				return err
			}
		case "update":
			applySRv6(uiOut, *config)
		case "back":
			b, _ := json.MarshalIndent(config, "", "  ")
			os.WriteFile(SRv6ConfigFile, b, 0644)
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
				askInput(prompter, "MTU", &mtuStr, validateNumber)
				fmt.Sscanf(mtuStr, "%d", &c.MTU)
			}
		}
	}
}

func showSRv6Status(uiOut *ui.UI, config SRv6Config) {
	uiOut.Info("SRv6 Carriers Status:")
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
