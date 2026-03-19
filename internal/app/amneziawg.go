package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

func randomInt(min, max int64) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min+1))
	return fmt.Sprintf("%d", n.Int64()+min)
}

func validateAwgParam(val string, min, max int) error {
	v, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return errors.New("must be a number")
	}
	if v < min || v > max {
		return fmt.Errorf("must be between %d and %d", min, max)
	}
	return nil
}

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

	uiOut.HR()
	uiOut.Title("AmneziaWG (awg-quick) Tunnel Generator")
	uiOut.Dim("WireGuard fork with obfuscation to bypass DPI")
	uiOut.HR()

	// 1. 独立检测模块和工具
	hasModule := sys.Run("modprobe", "-n", "amneziawg") == nil
	hasTools := requireCommands(nil, "awg", "awg-quick") == nil

	if !hasModule || !hasTools {
		if !hasModule && !hasTools {
			uiOut.Warn("AmneziaWG kernel module and tools are both missing.")
		} else if !hasModule {
			uiOut.Warn("AmneziaWG kernel module is missing (driver not found).")
		} else {
			uiOut.Warn("AmneziaWG tools (awg/awg-quick) are missing.")
		}

		ok, err := askConfirm(prompter, "Install/Fix missing AmneziaWG components from source?", false)
		if err != nil {
			return err
		}
		if ok {
			if !hasModule {
				if err := installAwgModule(uiOut, prompter); err != nil {
					return err
				}
			}
			if !hasTools {
				if err := installAwgTools(uiOut, prompter); err != nil {
					return err
				}
			}
			uiOut.Ok("AmneziaWG components installed/repaired")
		} else {
			return errors.New("missing required AmneziaWG components")
		}
	}

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

	uiOut.Info("AmneziaWG Obfuscation Parameters")
	mode := "manual"
	_ = prompter.Select("How to configure obfuscation parameters?", []ui.Option{
		{Label: "Set manually (with randomized defaults)", Value: "manual"},
		{Label: "Paste parameter string (Jc,Jmin,Jmax,S1,S2,H1,H2,H3,H4)", Value: "paste"},
	}, &mode)

	if mode == "paste" {
		var pStr string
		if err := askInput(prompter, "Paste parameter string", &pStr, func(v string) error {
			v = strings.TrimSpace(v)
			parts := strings.Split(v, ",")
			if len(parts) != 9 {
				return errors.New("must have 9 parts separated by commas")
			}
			// Strict range check for each pasted part
			// Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4
			ranges := [][]int{{1, 128}, {1, 1280}, {1, 1280}, {0, 1280}, {0, 1280}, {1, 2147483647}, {1, 2147483647}, {1, 2147483647}, {1, 2147483647}}
			for i, p := range parts {
				if err := validateAwgParam(p, ranges[i][0], ranges[i][1]); err != nil {
					return fmt.Errorf("part %d (%s) invalid: %w", i+1, p, err)
				}
			}
			jmin, _ := strconv.Atoi(parts[1])
			jmax, _ := strconv.Atoi(parts[2])
			if jmax < jmin {
				return errors.New("pasted parameters: Jmax must be >= Jmin")
			}
			return nil
		}); err != nil {
			return err
		}
		parts := strings.Split(strings.TrimSpace(pStr), ",")
		cfg.Jc, cfg.Jmin, cfg.Jmax, cfg.S1, cfg.S2 = parts[0], parts[1], parts[2], parts[3], parts[4]
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = parts[5], parts[6], parts[7], parts[8]
	} else {
		// Manual input with strict validation and randomized defaults
		cfg.Jc = askDefault(prompter, "Jc (Junk packets count [1-128])", randomInt(3, 10), func(s string) error { return validateAwgParam(s, 1, 128) })
		cfg.Jmin = askDefault(prompter, "Jmin (Min junk packet size [1-1280])", randomInt(30, 100), func(s string) error { return validateAwgParam(s, 1, 1280) })
		cfg.Jmax = askDefault(prompter, "Jmax (Max junk packet size [1-1280])", randomInt(500, 1200), func(s string) error {
			if err := validateAwgParam(s, 1, 1280); err != nil {
				return err
			}
			jminVal, _ := strconv.Atoi(cfg.Jmin)
			jmaxVal, _ := strconv.Atoi(s)
			if jmaxVal < jminVal {
				return fmt.Errorf("Jmax must be greater than Jmin (%d)", jminVal)
			}
			return nil
		})
		cfg.S1 = askDefault(prompter, "S1 (Initiation packet padding [0-1280])", randomInt(15, 150), func(s string) error { return validateAwgParam(s, 0, 1280) })
		cfg.S2 = askDefault(prompter, "S2 (Response packet padding [0-1280])", randomInt(15, 150), func(s string) error { return validateAwgParam(s, 0, 1280) })
		cfg.H1 = askDefault(prompter, "H1 (Magic Header 1 [non-zero 32-bit])", randomInt(1000, 2147483647), func(s string) error { return validateAwgParam(s, 1, 2147483647) })
		cfg.H2 = askDefault(prompter, "H2 (Magic Header 2 [non-zero 32-bit])", randomInt(1000, 2147483647), func(s string) error { return validateAwgParam(s, 1, 2147483647) })
		cfg.H3 = askDefault(prompter, "H3 (Magic Header 3 [non-zero 32-bit])", randomInt(1000, 2147483647), func(s string) error { return validateAwgParam(s, 1, 2147483647) })
		cfg.H4 = askDefault(prompter, "H4 (Magic Header 4 [non-zero 32-bit])", randomInt(1000, 2147483647), func(s string) error { return validateAwgParam(s, 1, 2147483647) })
	}

	obfsStr := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s",
		cfg.Jc, cfg.Jmin, cfg.Jmax, cfg.S1, cfg.S2, cfg.H1, cfg.H2, cfg.H3, cfg.H4)
	uiOut.Ok("Obfuscation string for reference: " + obfsStr)

	uiOut.Info("Generating AmneziaWG key pair...")
	privBytes, err := exec.Command("awg", "genkey").Output()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	priv := strings.TrimSpace(string(privBytes))

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
	if err := askInput(prompter, "MTU (blank = default 1420)", &mtu, validateNumber); err != nil {
		return err
	}
	cfg.MTU = mtu

	table := "off"
	if err := askInput(prompter, "Table (off/auto/number, blank = off)", &table, nil); err != nil {
		return err
	}
	cfg.Table = table

	if cfg.Endpoint != "" {
		keepalive := "25"
		if err := askInput(prompter, "PersistentKeepalive in seconds (0 = disable, blank = unset)", &keepalive, validateNumber); err != nil {
			return err
		}
		cfg.Keepalive = keepalive
	} else {
		cfg.Keepalive = ""
	}

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

func askDefault(prompter *ui.Prompter, title, def string, validate func(string) error) string {
	val := def
	_ = askInput(prompter, fmt.Sprintf("%s (blank = %s)", title, def), &val, func(v string) error {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		if validate != nil {
			return validate(v)
		}
		return nil
	})
	val = strings.TrimSpace(val)
	if val == "" {
		return def
	}
	return val
}

func ensureKernelHeaders(uiOut *ui.UI, prompter *ui.Prompter) error {
	out, err := sys.Output("uname", "-r")
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}
	kernelVersion := strings.TrimSpace(out)
	headerPath := fmt.Sprintf("/lib/modules/%s/build", kernelVersion)

	if _, err := os.Stat(headerPath); err == nil {
		return nil
	}

	uiOut.Warn("Kernel headers for " + kernelVersion + " not found.")

	// Check architecture
	archOut, _ := sys.Output("uname", "-m")
	arch := strings.TrimSpace(archOut)
	isArm := strings.HasPrefix(arch, "arm") || strings.HasPrefix(arch, "aarch64")

	if isArm {
		uiOut.Warn("ATTENTION: You are on an ARM platform (e.g., Raspberry Pi, Jetson, etc.).")
		uiOut.Warn("Installing generic linux-headers might NOT work or could even be incorrect for your board.")
		uiOut.Warn("ARM users should usually install headers via their board's specific package manager.")
		uiOut.Warn("Examples: 'apt install raspberrypi-kernel-headers' or 'armbian-config'.")
	}

	ok, err := askConfirm(prompter, "Try to install linux-headers for your kernel automatically?", !isArm)
	if err != nil || !ok {
		return errors.New("missing kernel headers (user declined auto-install)")
	}

	uiOut.Info("Installing kernel headers...")
	// Try specific version first
	pkgName := "linux-headers-" + kernelVersion
	if err := sys.Run("apt", "install", "-y", pkgName); err != nil {
		uiOut.Warn("Failed to install " + pkgName + ", trying generic linux-headers-amd64/arm64...")
		genericPkg := "linux-headers-amd64"
		if strings.HasPrefix(arch, "aarch64") {
			genericPkg = "linux-headers-arm64"
		}
		if err := sys.Run("apt", "install", "-y", genericPkg); err != nil {
			return fmt.Errorf("failed to install generic headers (%s): %w", genericPkg, err)
		}
	}
	return nil
}

func installAwgModule(uiOut *ui.UI, prompter *ui.Prompter) error {
	for {
		if err := ensureBuildDeps(uiOut); err != nil {
			uiOut.Error("Failed to install build dependencies: " + err.Error())
			if ok, _ := askConfirm(prompter, "Retry installing dependencies?", true); ok {
				continue
			}
			return err
		}

		if err := ensureKernelHeaders(uiOut, prompter); err != nil {
			uiOut.Error("Kernel headers requirement failed: " + err.Error())
			if ok, _ := askConfirm(prompter, "Retry headers check/install?", true); ok {
				continue
			}
			return err
		}

		// Install Kernel Module via DKMS
		uiOut.Info("Cloning amneziawg-linux-kernel-module...")
		tmpDir := "/tmp/amneziawg-kernel-src"
		srcDir := "/usr/src/amneziawg-1.0.0"

		// Safety: if we are in the directory that is about to be deleted, move out
		cwd, _ := os.Getwd()
		if strings.HasPrefix(cwd, srcDir) || strings.HasPrefix(cwd, tmpDir) {
			os.Chdir("/")
		}

		os.RemoveAll(tmpDir)
		os.RemoveAll(srcDir)

		if err := sys.Run("git", "clone", "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git", tmpDir); err != nil {
			uiOut.Error("Failed to clone kernel module: " + err.Error())
			if ok, _ := askConfirm(prompter, "Retry cloning?", true); ok {
				continue
			}
			return fmt.Errorf("failed to clone: %w", err)
		}

		uiOut.Info("Preparing DKMS source directory...")
		if err := sys.Run("cp", "-r", filepath.Join(tmpDir, "src"), srcDir); err != nil {
			uiOut.Error("Failed to prepare dkms source: " + err.Error())
			if ok, _ := askConfirm(prompter, "Retry copying?", true); ok {
				continue
			}
			return fmt.Errorf("failed to prepare dkms source: %w", err)
		}
		os.RemoveAll(tmpDir)

		uiOut.Info("Registering and building AmneziaWG via DKMS...")
		sys.Run("dkms", "remove", "amneziawg/1.0.0", "--all") // Clean up
		if err := sys.Run("dkms", "add", "amneziawg/1.0.0"); err != nil {
			uiOut.Error("DKMS add failed: " + err.Error())
		} else if err := sys.Run("dkms", "build", "amneziawg/1.0.0"); err != nil {
			uiOut.Error("DKMS build failed: " + err.Error())
		} else if err := sys.Run("dkms", "install", "amneziawg/1.0.0"); err != nil {
			uiOut.Error("DKMS install failed: " + err.Error())
		} else {
			// Success
			uiOut.Ok("AmneziaWG kernel module installed via DKMS")
			return nil
		}

		if ok, _ := askConfirm(prompter, "Installation failed. Retry the whole process?", true); !ok {
			break
		}
	}
	return errors.New("installation aborted by user after failure")
}

func installAwgTools(uiOut *ui.UI, prompter *ui.Prompter) error {
	for {
		if err := ensureBuildDeps(uiOut); err != nil {
			return err
		}

		uiOut.Info("Cloning amneziawg-tools...")
		toolsDir := "/tmp/amneziawg-tools"
		os.RemoveAll(toolsDir)

		if err := sys.Run("git", "clone", "https://github.com/amnezia-vpn/amneziawg-tools.git", toolsDir); err != nil {
			uiOut.Error("Failed to clone tools: " + err.Error())
			if ok, _ := askConfirm(prompter, "Retry cloning?", true); ok {
				continue
			}
			return fmt.Errorf("failed to clone tools: %w", err)
		}

		uiOut.Info("Building amneziawg-tools Debian package...")
		buildCmd := exec.Command("dpkg-buildpackage", "-b", "-uc", "-us")
		buildCmd.Dir = toolsDir
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr

		if err := buildCmd.Run(); err != nil {
			uiOut.Warn("Debian package build failed. Falling back to make install...")
			if err := sys.Run("make", "-C", filepath.Join(toolsDir, "src")); err != nil {
				return fmt.Errorf("failed to make tools: %w", err)
			}
			if err := sys.Run("make", "-C", filepath.Join(toolsDir, "src"), "install"); err != nil {
				return fmt.Errorf("failed to install tools: %w", err)
			}
		} else {
			uiOut.Info("Installing generated Debian packages...")
			// dpkg-buildpackage puts the .deb files in the parent directory (/tmp)
			installCmd := exec.Command("bash", "-c", "apt install -y /tmp/amneziawg*.deb")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				uiOut.Error("Failed to install the .deb packages: " + err.Error())
				if ok, _ := askConfirm(prompter, "Retry installation process?", true); ok {
					continue
				}
				return fmt.Errorf("deb installation failed: %w", err)
			}
		}

		// Clean up
		os.RemoveAll(toolsDir)
		exec.Command("bash", "-c", "rm -f /tmp/amneziawg*.deb /tmp/amneziawg*.buildinfo /tmp/amneziawg*.changes").Run()
		return nil
	}
}

func ensureBuildDeps(uiOut *ui.UI) error {
	if !sys.LookPath("apt") {
		return errors.New("apt not found; install build-essential, git, dkms manually")
	}
	uiOut.Info("Installing build dependencies...")
	args := []string{"install", "-y", "build-essential", "git", "make", "dkms", "debhelper", "pkg-config", "dpkg-dev"}
	return sys.Run("apt", args...)
}

func installAmneziaWG(uiOut *ui.UI, prompter *ui.Prompter) error {
	// Keep for backward compatibility if needed, but we use split functions now
	if err := installAwgModule(uiOut, prompter); err != nil {
		return err
	}
	return installAwgTools(uiOut, prompter)
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

func printAwgNextSteps(cfg *AmneziaWGConfig, uiOut *ui.UI) {
	uiOut.HR()
	uiOut.Title("Configuration Summary")
	fmt.Fprintf(uiOut.Out, "  Interface: %s\n", cfg.Interface)
	fmt.Fprintf(uiOut.Out, "  Local Public Key: %s\n", cfg.LocalPub)
	fmt.Fprintf(uiOut.Out, "  Obfuscation Params: %s,%s,%s,%s,%s,%s,%s,%s,%s\n",
		cfg.Jc, cfg.Jmin, cfg.Jmax, cfg.S1, cfg.S2, cfg.H1, cfg.H2, cfg.H3, cfg.H4)
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
