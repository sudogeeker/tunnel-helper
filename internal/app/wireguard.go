package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type WireGuardConfig struct {
	Name       string
	Interface  string
	InnerCIDR  string
	ListenPort string
	Endpoint   string
	LocalPriv  string
	LocalPub   string
	RemotePub  string
	MTU        string
	Table      string
	Keepalive  string
	WgDir      string
	ConfFile   string
}

func runWireguard(uiOut *ui.UI, prompter *ui.Prompter) error {
	cfg := &WireGuardConfig{
		WgDir: "/etc/wireguard",
	}

	if err := requireCommands(uiOut, "wg", "wg-quick"); err != nil {
		uiOut.Warn("WireGuard not installed. Please install 'wireguard-tools'.")
		ok, err := askConfirm(prompter, "Install wireguard-tools now via apt?", false)
		if err != nil {
			return err
		}
		if ok {
			if !sys.LookPath("apt") {
				return errors.New("apt not found; install manually")
			}
			uiOut.Info("Running apt update...")
			sys.Run("apt", "update")
			uiOut.Info("Installing wireguard and wireguard-tools...")
			if err := sys.Run("apt", "install", "-y", "wireguard", "wireguard-tools"); err != nil {
				return fmt.Errorf("failed to install wireguard: %w", err)
			}
			uiOut.Ok("WireGuard installed")
		} else {
			return errors.New("missing wg command")
		}
	}

	uiOut.HR()
	uiOut.Title("WireGuard (wg-quick) Tunnel Generator")
	uiOut.Dim("Simple, fast, modern VPN protocol")
	uiOut.HR()

	name := "prod1"
	if err := askInput(prompter, "Tunnel name (interface: wg-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = name
	cfg.Interface = "wg-" + name

	if isWgIfUsed(cfg.Interface) {
		uiOut.Warn("Interface " + cfg.Interface + " already exists")
		ok, err := askConfirm(prompter, "Continue anyway? This will overwrite config", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	insideEnv := strings.TrimSpace(os.Getenv("TUNNEL_INSIDE_ADDR"))
	if insideEnv != "" {
		innerCIDR, _, err := parseTunnelInsideAddrEnv(insideEnv)
		if err != nil {
			return err
		}
		cfg.InnerCIDR = innerCIDR
		uiOut.Info("Inner address from TUNNEL_INSIDE_ADDR: " + cfg.InnerCIDR)
	} else {
		uiOut.Info("Inner address configuration - leave blank to skip")
		inner := "fd00:cafe::0/127"
		if err := askInput(prompter, "Local inner address/CIDR (blank = no inner address)", &inner, nil); err != nil {
			return err
		}
		cfg.InnerCIDR = strings.TrimSpace(inner)
	}

	if cfg.InnerCIDR != "" {
		if strings.Contains(cfg.InnerCIDR, ",") {
			uiOut.Info("Detected dual-stack config")
		} else {
			ipStr := strings.Split(cfg.InnerCIDR, "/")[0]
			ip := net.ParseIP(ipStr)
			if ip != nil {
				if ip.To4() != nil {
					uiOut.Info("Detected IPv4 inner address")
				} else {
					uiOut.Info("Detected IPv6 inner address")
				}
			}
		}
	}

	port := ""
	if err := askInput(prompter, "Local listen port (blank = do not set ListenPort)", &port, func(v string) error {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		if !isDigits(v) {
			return errors.New("must be a number")
		}
		return nil
	}); err != nil {
		return err
	}
	cfg.ListenPort = port

	uiOut.Info("Endpoint configuration - leave blank if this is a passive receiver")
	uiOut.Info("Format: IP or IP:Port or [IPv6]:Port")
	endpoint := ""
	if err := askInput(prompter, "Remote Endpoint (blank = none)", &endpoint, nil); err != nil {
		return err
	}

	endpoint = strings.TrimSpace(endpoint)
	if endpoint != "" {
		if !strings.Contains(endpoint, ":") || (strings.Count(endpoint, ":") > 1 && !strings.Contains(endpoint, "[")) {
			// Doesn't have port, ask for it
			ePort := "51820"
			if err := askInput(prompter, "Endpoint Port", &ePort, func(v string) error {
				if !isDigits(v) {
					return errors.New("must be a number")
				}
				return nil
			}); err != nil {
				return err
			}
			ip := net.ParseIP(endpoint)
			if ip != nil && ip.To4() == nil {
				// IPv6
				endpoint = fmt.Sprintf("[%s]:%s", endpoint, ePort)
			} else {
				endpoint = fmt.Sprintf("%s:%s", endpoint, ePort)
			}
		}
		cfg.Endpoint = endpoint
	}

	uiOut.Info("Generating WireGuard key pair...")
	privBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	priv := strings.TrimSpace(string(privBytes))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv)
	pubBytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate public key: %w", err)
	}
	pub := strings.TrimSpace(string(pubBytes))

	cfg.LocalPriv = priv
	cfg.LocalPub = pub
	uiOut.Ok("Local public key: " + cfg.LocalPub)

	remotePub := ""
	if err := askInput(prompter, "Remote public key (blank to fill later manually)", &remotePub, nil); err != nil {
		return err
	}
	cfg.RemotePub = strings.TrimSpace(remotePub)

	mtu := "1420"
	if err := askInput(prompter, "MTU (blank = default 1420)", &mtu, validateNumber); err != nil {
		return err
	}
	cfg.MTU = mtu

	table := "off"
	if err := askInput(prompter, "Table (off/auto/number, blank = off)", &table, nil); err != nil {
		return err
	}
	cfg.Table = table

	keepaliveDef := ""
	if cfg.Endpoint != "" {
		keepaliveDef = "25"
	}
	keepalive := keepaliveDef
	if err := askInput(prompter, "PersistentKeepalive in seconds (0 = disable, blank = unset)", &keepalive, validateNumber); err != nil {
		return err
	}
	cfg.Keepalive = keepalive

	cfg.ConfFile = filepath.Join(cfg.WgDir, cfg.Interface+".conf")
	if fileExists(cfg.ConfFile) {
		uiOut.Warn("Config file exists: " + cfg.ConfFile)
		ok, err := askConfirm(prompter, "Overwrite?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	if err := os.MkdirAll(cfg.WgDir, 0700); err != nil {
		return err
	}

	conf := buildWgConf(cfg)
	if err := os.WriteFile(cfg.ConfFile, []byte(conf), 0600); err != nil {
		return err
	}
	uiOut.Ok("Wrote: " + cfg.ConfFile)

	uiOut.Info("Enabling and starting interface via systemd...")
	if err := sys.Run("systemctl", "enable", "--now", "wg-quick@"+cfg.Interface); err != nil {
		uiOut.Warn("Failed to enable/start wg-quick@" + cfg.Interface)
	} else {
		uiOut.Ok("Interface started")
	}

	printWgNextSteps(cfg, uiOut)
	return nil
}

func isWgIfUsed(iface string) bool {
	out, err := sys.Output("ip", "link", "show", iface)
	if err != nil {
		return false
	}
	return strings.Contains(out, iface)
}

func buildWgConf(cfg *WireGuardConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.LocalPriv)

	if cfg.Table != "" {
		fmt.Fprintf(&b, "Table = %s\n", cfg.Table)
	}
	if cfg.InnerCIDR != "" {
		fmt.Fprintf(&b, "Address = %s\n", cfg.InnerCIDR)
	}
	if cfg.ListenPort != "" {
		fmt.Fprintf(&b, "ListenPort = %s\n", cfg.ListenPort)
	}
	if cfg.MTU != "" {
		fmt.Fprintf(&b, "MTU = %s\n", cfg.MTU)
	}

	if cfg.RemotePub != "" {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", cfg.RemotePub)
		if cfg.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", cfg.Endpoint)
		}
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
		if cfg.Keepalive != "" && cfg.Keepalive != "0" {
			fmt.Fprintf(&b, "PersistentKeepalive = %s\n", cfg.Keepalive)
		}
	} else {
		b.WriteString("\n# [Peer]\n")
		b.WriteString("# PublicKey = <Insert Remote Public Key Here>\n")
		if cfg.Endpoint != "" {
			fmt.Fprintf(&b, "# Endpoint = %s\n", cfg.Endpoint)
		}
		b.WriteString("# AllowedIPs = 0.0.0.0/0, ::/0\n")
		if cfg.Keepalive != "" && cfg.Keepalive != "0" {
			fmt.Fprintf(&b, "# PersistentKeepalive = %s\n", cfg.Keepalive)
		}
	}

	return b.String()
}

func printWgNextSteps(cfg *WireGuardConfig, uiOut *ui.UI) {
	uiOut.HR()
	uiOut.Title("Configuration Summary")
	fmt.Fprintf(uiOut.Out, "  Interface: %s\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  Local Public Key: %s\n", cfg.LocalPub)
	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "  Inner Address: %s\n", cfg.InnerCIDR)
	}
	if cfg.ListenPort != "" {
		fmt.Fprintf(uiOut.Out, "  Listen Port: %s\n", cfg.ListenPort)
	}
	if cfg.Endpoint != "" {
		fmt.Fprintf(uiOut.Out, "  Remote Endpoint: %s\n", cfg.Endpoint)
	}

	uiOut.HR()
	uiOut.Warn("Remote Configuration (Reference):")
	fmt.Fprintf(uiOut.Out, "[Interface]\nPrivateKey = <Remote Private Key>\n")
	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "Address = <Remote Inner Address>\n")
	}
	fmt.Fprintf(uiOut.Out, "ListenPort = <Remote Port>\n")
	mtu := cfg.MTU
	if mtu == "" {
		mtu = "1420"
	}
	fmt.Fprintf(uiOut.Out, "MTU = %s\n\n", mtu)
	fmt.Fprintf(uiOut.Out, "[Peer]\nPublicKey = %s\n", cfg.LocalPub)
	if cfg.ListenPort != "" {
		fmt.Fprintf(uiOut.Out, "Endpoint = <Your IP>:%s\n", cfg.ListenPort)
	}
	fmt.Fprintf(uiOut.Out, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	if cfg.Keepalive != "" && cfg.Keepalive != "0" {
		fmt.Fprintf(uiOut.Out, "PersistentKeepalive = %s\n", cfg.Keepalive)
	}

	uiOut.HR()
	uiOut.Title("Next steps on this machine:")
	fmt.Fprintf(uiOut.Out, "  # 1. Edit config to add remote public key if omitted\n")
	fmt.Fprintf(uiOut.Out, "  nano %s\n\n", cfg.ConfFile)
	fmt.Fprintf(uiOut.Out, "  # 2. Start WireGuard interface\n")
	fmt.Fprintf(uiOut.Out, "  wg-quick up %s\n\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  # 3. Check interface status\n")
	fmt.Fprintf(uiOut.Out, "  wg show %s\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  ip link show %s\n", cfg.Interface)
	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "  ip addr show %s\n", cfg.Interface)
	}
	fmt.Fprintf(uiOut.Out, "\n  # 4. Enable at boot (systemd)\n")
	fmt.Fprintf(uiOut.Out, "  systemctl enable wg-quick@%s\n", cfg.Interface)

	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "\n  # 5. Test connectivity\n")
		fmt.Fprintf(uiOut.Out, "  ping <remote-inner-ip> -I %s\n", cfg.Interface)
	}
	uiOut.HR()
}
