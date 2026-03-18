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

type AmneziaWGConfig struct {
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
	AwgDir     string
	ConfFile   string

	// AmneziaWG specific
	Jc   string
	Jmin string
	Jmax string
	S1   string
	S2   string
	H1   string
	H2   string
	H3   string
	H4   string
}

func runAmneziaWG(uiOut *ui.UI, prompter *ui.Prompter) error {
	cfg := &AmneziaWGConfig{
		AwgDir: "/etc/amnezia/amneziawg",
	}

	if err := requireCommands(uiOut, "awg", "awg-quick"); err != nil {
		uiOut.Warn("AmneziaWG not installed (missing awg or awg-quick).")
		ok, err := askConfirm(prompter, "Compile and install AmneziaWG from source?", false)
		if err != nil {
			return err
		}
		if ok {
			if err := installAmneziaWG(uiOut); err != nil {
				return fmt.Errorf("failed to install AmneziaWG: %w", err)
			}
			uiOut.Ok("AmneziaWG installed")
		} else {
			return errors.New("missing awg command")
		}
	}

	uiOut.HR()
	uiOut.Title("AmneziaWG (awg-quick) Tunnel Generator")
	uiOut.Dim("WireGuard fork with obfuscation to bypass DPI")
	uiOut.HR()

	name := "prod1"
	if err := askInput(prompter, "Tunnel name (interface: awg-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = name
	cfg.Interface = "awg-" + name

	if isAwgIfUsed(cfg.Interface) {
		uiOut.Warn("Interface " + cfg.Interface + " already exists")
		ok, err := askConfirm(prompter, "Continue anyway? This will overwrite config", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	uiOut.Info("Inner address configuration - leave blank to skip")
	inner := "fd00:cafe::0/127"
	if err := askInput(prompter, "Local inner address/CIDR (blank = no inner address)", &inner, nil); err != nil {
		return err
	}
	cfg.InnerCIDR = strings.TrimSpace(inner)

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

	uiOut.Info("AmneziaWG Obfuscation Parameters")
	cfg.Jc = askDefault(prompter, "Jc", "120")
	cfg.Jmin = askDefault(prompter, "Jmin", "50")
	cfg.Jmax = askDefault(prompter, "Jmax", "1000")
	cfg.S1 = askDefault(prompter, "S1", "0")
	cfg.S2 = askDefault(prompter, "S2", "0")
	cfg.H1 = askDefault(prompter, "H1", "1")
	cfg.H2 = askDefault(prompter, "H2", "2")
	cfg.H3 = askDefault(prompter, "H3", "3")
	cfg.H4 = askDefault(prompter, "H4", "4")

	uiOut.Info("Generating AmneziaWG key pair...")
	priv, err := sys.Output("awg", "genkey")
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	priv = strings.TrimSpace(priv)

	cmd := exec.Command("awg", "pubkey")
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
	if err := askInput(prompter, "MTU (blank = default 1420)", &mtu, nil); err != nil {
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
	if err := askInput(prompter, "PersistentKeepalive in seconds (0 = disable, blank = unset)", &keepalive, nil); err != nil {
		return err
	}
	cfg.Keepalive = keepalive

	cfg.ConfFile = filepath.Join(cfg.AwgDir, cfg.Interface+".conf")
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

	if err := os.MkdirAll(cfg.AwgDir, 0700); err != nil {
		return err
	}

	conf := buildAwgConf(cfg)
	if err := os.WriteFile(cfg.ConfFile, []byte(conf), 0600); err != nil {
		return err
	}
	uiOut.Ok("Wrote: " + cfg.ConfFile)

	uiOut.Info("Enabling and starting interface via systemd...")
	if err := sys.Run("systemctl", "enable", "--now", "awg-quick@"+cfg.Interface); err != nil {
		uiOut.Warn("Failed to enable/start awg-quick@" + cfg.Interface)
	} else {
		uiOut.Ok("Interface started")
	}

	printAwgNextSteps(cfg, uiOut)
	return nil
}

func askDefault(prompter *ui.Prompter, title, def string) string {
	val := def
	_ = askInput(prompter, fmt.Sprintf("%s (blank = %s)", title, def), &val, nil)
	val = strings.TrimSpace(val)
	if val == "" {
		return def
	}
	return val
}

func installAmneziaWG(uiOut *ui.UI) error {
	if !sys.LookPath("apt") {
		return errors.New("apt not found; install manually")
	}

	unameR, err := sys.Output("uname", "-r")
	if err != nil {
		return fmt.Errorf("failed to get uname -r: %w", err)
	}
	unameR = strings.TrimSpace(unameR)

	uiOut.Info("Running apt update...")
	sys.Run("apt", "update")

	uiOut.Info("Installing build dependencies...")
	deps := []string{"build-essential", "git", "make"}
	args := append([]string{"install", "-y"}, deps...)
	if err := sys.Run("apt", args...); err != nil {
		return fmt.Errorf("failed to install build dependencies: %w", err)
	}

	uiOut.Info("Attempting to install linux-headers for current kernel...")
	if err := sys.Run("apt", "install", "-y", "linux-headers-"+unameR); err != nil {
		uiOut.Warn(fmt.Sprintf("Could not install linux-headers-%s. Kernel module compilation might fail.", unameR))
		uiOut.Info("Attempting fallback: installing linux-headers-amd64 and linux-headers-generic...")
		sys.Run("apt", "install", "-y", "linux-headers-amd64", "linux-headers-generic")
	}

	// Install Kernel Module
	uiOut.Info("Cloning amneziawg-linux-kernel...")
	os.RemoveAll("/tmp/amneziawg-linux-kernel")
	if err := sys.Run("git", "clone", "https://github.com/amnezia-vpn/amneziawg-linux-kernel.git", "/tmp/amneziawg-linux-kernel"); err != nil {
		return fmt.Errorf("failed to clone kernel module: %w", err)
	}

	uiOut.Info("Building kernel module...")
	if err := sys.Run("make", "-C", "/tmp/amneziawg-linux-kernel/src", "module"); err != nil {
		return fmt.Errorf("failed to make kernel module: %w", err)
	}

	uiOut.Info("Installing kernel module...")
	if err := sys.Run("make", "-C", "/tmp/amneziawg-linux-kernel/src", "module-install"); err != nil {
		return fmt.Errorf("failed to install kernel module: %w", err)
	}

	// Install Tools
	uiOut.Info("Cloning amneziawg-tools...")
	os.RemoveAll("/tmp/amneziawg-tools")
	if err := sys.Run("git", "clone", "https://github.com/amnezia-vpn/amneziawg-tools.git", "/tmp/amneziawg-tools"); err != nil {
		return fmt.Errorf("failed to clone tools: %w", err)
	}

	uiOut.Info("Building tools...")
	if err := sys.Run("make", "-C", "/tmp/amneziawg-tools/src"); err != nil {
		return fmt.Errorf("failed to make tools: %w", err)
	}

	uiOut.Info("Installing tools...")
	if err := sys.Run("make", "-C", "/tmp/amneziawg-tools/src", "install"); err != nil {
		return fmt.Errorf("failed to install tools: %w", err)
	}

	return nil
}

func isAwgIfUsed(iface string) bool {
	out, err := sys.Output("ip", "link", "show", iface)
	if err != nil {
		return false
	}
	return strings.Contains(out, iface)
}

func buildAwgConf(cfg *AmneziaWGConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.LocalPriv)

	if cfg.Jc != "" {
		fmt.Fprintf(&b, "Jc = %s\n", cfg.Jc)
	}
	if cfg.Jmin != "" {
		fmt.Fprintf(&b, "Jmin = %s\n", cfg.Jmin)
	}
	if cfg.Jmax != "" {
		fmt.Fprintf(&b, "Jmax = %s\n", cfg.Jmax)
	}
	if cfg.S1 != "" {
		fmt.Fprintf(&b, "S1 = %s\n", cfg.S1)
	}
	if cfg.S2 != "" {
		fmt.Fprintf(&b, "S2 = %s\n", cfg.S2)
	}
	if cfg.H1 != "" {
		fmt.Fprintf(&b, "H1 = %s\n", cfg.H1)
	}
	if cfg.H2 != "" {
		fmt.Fprintf(&b, "H2 = %s\n", cfg.H2)
	}
	if cfg.H3 != "" {
		fmt.Fprintf(&b, "H3 = %s\n", cfg.H3)
	}
	if cfg.H4 != "" {
		fmt.Fprintf(&b, "H4 = %s\n", cfg.H4)
	}

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

	b.WriteString("\n[Peer]\n")
	if cfg.RemotePub != "" {
		fmt.Fprintf(&b, "PublicKey = %s\n", cfg.RemotePub)
	} else {
		b.WriteString("PublicKey = <Insert Remote Public Key Here>\n")
	}

	if cfg.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", cfg.Endpoint)
	}

	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")

	if cfg.Keepalive != "" && cfg.Keepalive != "0" {
		fmt.Fprintf(&b, "PersistentKeepalive = %s\n", cfg.Keepalive)
	}

	return b.String()
}

func printAwgNextSteps(cfg *AmneziaWGConfig, uiOut *ui.UI) {
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
	fmt.Fprintf(uiOut.Out, "Jc = %s\nJmin = %s\nJmax = %s\nS1 = %s\nS2 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n",
		cfg.Jc, cfg.Jmin, cfg.Jmax, cfg.S1, cfg.S2, cfg.H1, cfg.H2, cfg.H3, cfg.H4)

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
	fmt.Fprintf(uiOut.Out, "  # 2. Start AmneziaWG interface\n")
	fmt.Fprintf(uiOut.Out, "  awg-quick up %s\n\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  # 3. Check interface status\n")
	fmt.Fprintf(uiOut.Out, "  awg show %s\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  ip link show %s\n", cfg.Interface)
	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "  ip addr show %s\n", cfg.Interface)
	}
	fmt.Fprintf(uiOut.Out, "\n  # 4. Enable at boot (systemd)\n")
	fmt.Fprintf(uiOut.Out, "  systemctl enable awg-quick@%s\n", cfg.Interface)

	if cfg.InnerCIDR != "" {
		fmt.Fprintf(uiOut.Out, "\n  # 5. Test connectivity\n")
		fmt.Fprintf(uiOut.Out, "  ping <remote-inner-ip> -I %s\n", cfg.Interface)
	}
	uiOut.HR()
}
