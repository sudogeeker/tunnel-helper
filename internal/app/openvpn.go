package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type OpenVPNConfig struct {
	Name                 string
	Role                 string // "listener" or "initiator"
	Protocol             string // "udp" or "tcp"
	Port                 string
	LocalUnder           string
	RemoteUnder          string
	Iface                string
	LocalInner           string
	RemoteInner          string
	MTU                  string
	DCO                  bool
	AuthMethod           string // "rpk"
	RPKLocalCertPath     string
	RPKLocalKeyPath      string
	RPKLocalFingerprint  string
	RPKRemoteFingerprint string
	ConfPath             string
}

const (
	OVPNAuthRPK = "rpk"
)

func runOpenVPN(uiOut *ui.UI, prompter *ui.Prompter) error {
	uiOut.HR()
	uiOut.Title("OpenVPN (DCO)")
	uiOut.HR()

	if err := checkOpenVPNPackages(uiOut, prompter); err != nil {
		return err
	}

	cfg := &OpenVPNConfig{DCO: true}

	if err := collectOpenVPNInputs(cfg, uiOut, prompter); err != nil {
		return wrapAbort(err)
	}

	if err := generateOpenVPNCredentials(cfg, uiOut, prompter); err != nil {
		return wrapAbort(err)
	}

	if err := writeOpenVPNConfig(cfg, uiOut); err != nil {
		return err
	}

	printOpenVPNNextSteps(cfg, uiOut)
	return nil
}

func checkOpenVPNPackages(uiOut *ui.UI, prompter *ui.Prompter) error {
	required := []string{"openvpn", "dkms", "openvpn-dco-dkms"}
	missing := []string{}

	for _, pkg := range required {
		out, err := sys.Output("dpkg-query", "-W", "-f=${Status}", pkg)
		if err != nil || !strings.Contains(out, "install ok installed") {
			missing = append(missing, pkg)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	uiOut.Warn("Missing OpenVPN packages:")
	for _, pkg := range missing {
		uiOut.Warn("  - " + pkg)
	}

	ok, err := askConfirm(prompter, "Attempt to install them now with apt-get?", true)
	if err != nil {
		return wrapAbort(err)
	}

	if ok {
		args := append([]string{"install", "-y"}, missing...)
		if err := sys.Run("apt-get", args...); err != nil {
			return fmt.Errorf("failed to install packages: %w", err)
		}
		uiOut.Ok("Packages installed successfully")
	}

	return nil
}

func collectOpenVPNInputs(cfg *OpenVPNConfig, uiOut *ui.UI, prompter *ui.Prompter) error {
	// Tunnel Name
	name := "tun1"
	if err := askInput(prompter, "Tunnel name (interface: ovpn-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = name
	cfg.Iface = "ovpn-" + name

	// Role
	roleChoice := "1"
	if err := askSelectRaw(prompter, "Role in the connection", []ui.Option{
		{Label: "1) Listener (Server - waits for connection)", Value: "1"},
		{Label: "2) Initiator (Client - initiates connection)", Value: "2"},
	}, &roleChoice); err != nil {
		return err
	}
	if roleChoice == "1" {
		cfg.Role = "listener"
	} else {
		cfg.Role = "initiator"
	}

	// Protocol
	protoChoice := "1"
	if err := askSelectRaw(prompter, "Protocol", []ui.Option{
		{Label: "1) UDP (Recommended for VPN)", Value: "1"},
		{Label: "2) TCP", Value: "2"},
	}, &protoChoice); err != nil {
		return err
	}
	if protoChoice == "1" {
		cfg.Protocol = "udp"
	} else {
		cfg.Protocol = "tcp"
	}

	// Port
	port := "1194"
	portPrompt := "Listen Port"
	if cfg.Role == "initiator" {
		portPrompt = "Remote Port (to connect to)"
	}
	if err := askInput(prompter, portPrompt, &port, validateNumber); err != nil {
		return err
	}
	cfg.Port = port

	// Remote / Local IPs
	if cfg.Role == "initiator" {
		remote := ""
		if err := askInput(prompter, "Remote Underlay IP (Target Server)", &remote, requireNonEmpty); err != nil {
			return err
		}
		cfg.RemoteUnder = remote
	} else {
		// Listener
		local := "%any"
		if err := askInput(prompter, "Local Listen IP (or %any)", &local, nil); err != nil {
			return err
		}
		cfg.LocalUnder = normalizeAny(local)

		remote := ""
		if err := askInput(prompter, "Remote Underlay IP (Optional, limits inbound to this IP)", &remote, nil); err != nil {
			return err
		}
		if remote != "" {
			cfg.RemoteUnder = remote
		}
	}

	// Inner IPs
	insideEnv := strings.TrimSpace(os.Getenv("TUNNEL_INSIDE_ADDR"))
	if insideEnv != "" {
		innerCIDR, _, err := parseTunnelInsideAddrEnv(insideEnv)
		if err != nil {
			return err
		}
		// In P2P, we use the IP from CIDR as local, and let the user specify remote or try to guess.
		// If it's a CIDR like 10.0.0.1/30, local is 10.0.0.1.
		// For IPv6, we often want the /bits part.
		cfg.LocalInner = innerCIDR
		uiOut.Info("Local inner address from TUNNEL_INSIDE_ADDR: " + cfg.LocalInner)

		remoteInner := ""
		if err := askInput(prompter, "Remote Inner IP (e.g., 10.8.0.2)", &remoteInner, requireNonEmpty); err != nil {
			return err
		}
		cfg.RemoteInner = remoteInner
	} else {
		localInner := "10.8.0.1"
		remoteInner := "10.8.0.2"
		if cfg.Role == "initiator" {
			localInner = "10.8.0.2"
			remoteInner = "10.8.0.1"
		}
		if err := askInput(prompter, "Local Inner IP (e.g., 10.8.0.1)", &localInner, requireNonEmpty); err != nil {
			return err
		}
		cfg.LocalInner = localInner
		if err := askInput(prompter, "Remote Inner IP (e.g., 10.8.0.2)", &remoteInner, requireNonEmpty); err != nil {
			return err
		}
		cfg.RemoteInner = remoteInner
	}

	// MTU
	mtu := "1420"
	if err := askInput(prompter, "MTU", &mtu, validateNumber); err != nil {
		return err
	}
	cfg.MTU = mtu

	// DCO
	dco, err := askConfirm(prompter, "Enable DCO (Data Channel Offload)? [Highly Recommended]", true)
	if err != nil {
		return err
	}
	cfg.DCO = dco

	cfg.AuthMethod = OVPNAuthRPK

	return nil
}

func generateOpenVPNCredentials(cfg *OpenVPNConfig, uiOut *ui.UI, prompter *ui.Prompter) error {
	baseDir := "/etc/openvpn/server"
	if cfg.Role == "initiator" {
		baseDir = "/etc/openvpn/client"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	// RPK Mode
	cfg.RPKLocalCertPath = filepath.Join(baseDir, cfg.Iface+".crt")
	cfg.RPKLocalKeyPath = filepath.Join(baseDir, cfg.Iface+".key")

	if !fileExists(cfg.RPKLocalCertPath) || !fileExists(cfg.RPKLocalKeyPath) {
		uiOut.Info("Generating local self-signed certificate for Peer Fingerprint...")
		subj := fmt.Sprintf("/CN=%s", cfg.Iface)
		cmd := fmt.Sprintf("openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout %s -out %s -days 3650 -nodes -subj %s", cfg.RPKLocalKeyPath, cfg.RPKLocalCertPath, subj)
		if err := sys.Run("bash", "-c", cmd); err != nil {
			return fmt.Errorf("failed to generate local cert/key: %w", err)
		}
	}

	// Calculate local fingerprint
	out, err := sys.Output("openssl", "x509", "-in", cfg.RPKLocalCertPath, "-noout", "-fingerprint", "-sha256")
	if err != nil {
		return fmt.Errorf("failed to get local cert fingerprint: %w", err)
	}
	// Output looks like: SHA256 Fingerprint=AB:CD:EF...
	parts := strings.Split(out, "=")
	if len(parts) != 2 {
		return fmt.Errorf("unexpected fingerprint output: %s", out)
	}
	cfg.RPKLocalFingerprint = strings.TrimSpace(parts[1])

	uiOut.HR()
	uiOut.Ok("Your Local SHA256 Fingerprint (give this to the remote side):")
	fmt.Fprintf(uiOut.Out, "  %s\n", cfg.RPKLocalFingerprint)
	uiOut.HR()

	remoteFp := ""
	if err := askInput(prompter, "Remote SHA256 Fingerprint (leave blank to add later)", &remoteFp, nil); err != nil {
		return err
	}
	cfg.RPKRemoteFingerprint = strings.TrimSpace(remoteFp)

	return nil
}

func writeOpenVPNConfig(cfg *OpenVPNConfig, uiOut *ui.UI) error {
	baseDir := "/etc/openvpn/server"
	if cfg.Role == "initiator" {
		baseDir = "/etc/openvpn/client"
	}
	cfg.ConfPath = filepath.Join(baseDir, cfg.Iface+".conf")

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# OpenVPN Configuration: %s (%s)\n", cfg.Iface, cfg.Role))
	b.WriteString(fmt.Sprintf("dev %s\n", cfg.Iface))
	b.WriteString("dev-type tun\n")

	proto := cfg.Protocol
	if cfg.Protocol == "tcp" {
		if cfg.Role == "listener" {
			proto = "tcp-server"
		} else {
			proto = "tcp-client"
		}
	}
	b.WriteString(fmt.Sprintf("proto %s\n", proto))

	if cfg.Role == "listener" {
		if cfg.LocalUnder != "%any" && cfg.LocalUnder != "" {
			b.WriteString(fmt.Sprintf("local %s\n", cfg.LocalUnder))
		}
		b.WriteString(fmt.Sprintf("port %s\n", cfg.Port))
		if cfg.RemoteUnder != "" {
			b.WriteString(fmt.Sprintf("remote %s\n", cfg.RemoteUnder))
		}
	} else {
		b.WriteString(fmt.Sprintf("remote %s %s\n", cfg.RemoteUnder, cfg.Port))
		// Optional local port binding could be added, but usually clients use dynamic port
		b.WriteString("nobind\n")
	}

	if strings.Contains(cfg.LocalInner, ":") {
		// IPv6 P2P: ifconfig-ipv6 <local>/<bits> <remote>
		b.WriteString(fmt.Sprintf("ifconfig-ipv6 %s %s\n", cfg.LocalInner, cfg.RemoteInner))
	} else {
		// IPv4 P2P: ifconfig <local> <remote>
		localIP := cfg.LocalInner
		if strings.Contains(localIP, "/") {
			localIP = strings.Split(localIP, "/")[0]
		}
		b.WriteString(fmt.Sprintf("ifconfig %s %s\n", localIP, cfg.RemoteInner))
	}

	// Performance Optimizations
	b.WriteString("sndbuf 0\n")
	b.WriteString("rcvbuf 0\n")
	b.WriteString("fast-io\n")
	if cfg.MTU != "" {
		b.WriteString(fmt.Sprintf("tun-mtu %s\n", cfg.MTU))
	}
	b.WriteString("txqueuelen 10000\n")

	// Allow remote peer to use a dynamic source port or IP (crucial for NAT/ephemeral ports)
	b.WriteString("float\n")

	// Modern Ciphers
	b.WriteString("cipher AES-256-GCM\n")
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n")

	if !cfg.DCO {
		b.WriteString("disable-dco\n")
	}

	// Keepalive
	b.WriteString("keepalive 10 60\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")

	// Authentication
	if cfg.Role == "listener" {
		b.WriteString("tls-server\n")
		b.WriteString("dh none\n")
	} else {
		b.WriteString("tls-client\n")
	}
	b.WriteString(fmt.Sprintf("cert %s\n", filepath.Base(cfg.RPKLocalCertPath)))
	b.WriteString(fmt.Sprintf("key %s\n", filepath.Base(cfg.RPKLocalKeyPath)))

	if cfg.RPKRemoteFingerprint != "" {
		b.WriteString(fmt.Sprintf("peer-fingerprint \"%s\"\n", cfg.RPKRemoteFingerprint))
	} else {
		b.WriteString("# peer-fingerprint \"<REMOTE_FINGERPRINT_HERE>\"\n")
	}

	b.WriteString("verb 3\n")

	if err := os.WriteFile(cfg.ConfPath, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	uiOut.Ok("Wrote " + cfg.ConfPath)
	return nil
}

func printOpenVPNNextSteps(cfg *OpenVPNConfig, uiOut *ui.UI) {
	uiOut.HR()
	uiOut.Title("Configuration Summary")
	fmt.Fprintf(uiOut.Out, "Role: %s\n", cfg.Role)
	fmt.Fprintf(uiOut.Out, "Interface: %s\n", cfg.Iface)
	fmt.Fprintf(uiOut.Out, "Inner IP: %s -> %s\n", cfg.LocalInner, cfg.RemoteInner)
	fmt.Fprintf(uiOut.Out, "Auth: %s\n", cfg.AuthMethod)
	fmt.Fprintf(uiOut.Out, "Config File: %s\n", cfg.ConfPath)

	uiOut.HR()
	uiOut.Title("Next Steps")

	serviceName := fmt.Sprintf("openvpn-server@%s", cfg.Iface)
	if cfg.Role == "initiator" {
		serviceName = fmt.Sprintf("openvpn-client@%s", cfg.Iface)
	}

	fmt.Fprintf(uiOut.Out, "  systemctl enable --now %s\n", serviceName)
	fmt.Fprintf(uiOut.Out, "  systemctl status %s\n", serviceName)
	fmt.Fprintf(uiOut.Out, "  ip addr show %s\n", cfg.Iface)
	fmt.Fprintf(uiOut.Out, "  ping %s -I %s\n", cfg.RemoteInner, cfg.Iface)

	uiOut.HR()
	uiOut.Warn("Remote side needs:")
	fmt.Fprintf(uiOut.Out, "  - Opposite Role (%s)\n", map[string]string{"listener": "initiator", "initiator": "listener"}[cfg.Role])
	fmt.Fprintf(uiOut.Out, "  - Same Protocol and Port\n")
	fmt.Fprintf(uiOut.Out, "  - Flipped Inner IPs (ifconfig %s %s)\n", cfg.RemoteInner, cfg.LocalInner)
	fmt.Fprintf(uiOut.Out, "  - Your SHA256 Fingerprint: %s\n", cfg.RPKLocalFingerprint)
	if cfg.RPKRemoteFingerprint == "" {
		fmt.Fprintf(uiOut.Out, "  ! You must also edit %s and set their fingerprint\n", cfg.ConfPath)
	}
	uiOut.HR()
}
