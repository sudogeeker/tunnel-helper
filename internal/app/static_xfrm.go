package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

type StaticXfrmConfig struct {
	Name        string
	UnderlayFam int
	Device      string
	RemoteUnder string
	LocalUnder  string
	XfrmIf      string
	IfID        int
	InnerFam    int
	InnerCIDR   string
	IfaceDir    string
	IfaceFile   string

	// Manual Keying
	SpiIn   string
	SpiOut  string
	EncKey  string // 32 chars for aes128 (16 bytes) or 64 for aes256 (32 bytes)
	AuthKey string // 40 chars for sha1 (20 bytes) or 64 for sha256 (32 bytes)
	Algo    string // aes-gcm or aes-cbc+hmac-sha256
}

func runStaticXFRM(uiOut *ui.UI, prompter *ui.Prompter) error {
	cfg := &StaticXfrmConfig{
		IfaceDir: "/etc/network/interfaces.d",
	}

	uiOut.HR()
	uiOut.Title("Static XFRM (Manual Keying) Generator")
	uiOut.Dim("No IKE negotiation, no 500/4500 UDP needed")
	uiOut.HR()

	if err := collectStaticXfrmInputs(cfg, uiOut, prompter); err != nil {
		return err
	}

	cfg.IfaceFile = filepath.Join(cfg.IfaceDir, cfg.XfrmIf+".cfg")

	if fileExists(cfg.IfaceFile) {
		uiOut.Warn("File exists: " + cfg.IfaceFile)
		ok, err := askConfirm(prompter, "Overwrite?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	if err := os.MkdirAll(cfg.IfaceDir, 0755); err != nil {
		return err
	}

	iface := buildStaticXfrmIface(cfg)
	if err := os.WriteFile(cfg.IfaceFile, []byte(iface), 0644); err != nil {
		return err
	}
	uiOut.Ok("wrote: " + cfg.IfaceFile)

	if err := ensureInterfacesSource(uiOut, prompter); err != nil {
		return err
	}

	uiOut.Info("Bringing up interface " + cfg.XfrmIf + "...")
	if err := sys.Run("ifup", cfg.XfrmIf); err != nil {
		uiOut.Warn("Failed to bring up interface. Is it already up?")
	} else {
		uiOut.Ok("Interface is up")
	}

	printStaticXfrmNextSteps(cfg, uiOut)
	return nil
}

func collectStaticXfrmInputs(cfg *StaticXfrmConfig, uiOut *ui.UI, prompter *ui.Prompter) error {
	name := "static1"
	if err := askInput(prompter, "Tunnel name (interface: ipsec-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = name
	cfg.XfrmIf = "ipsec-" + name
	cfg.IfID = generateIfID(name)

	// Underlay
	if err := askSelect(prompter, "Underlay IP version", []ui.Option{
		{Label: "IPv4", Value: "4"},
		{Label: "IPv6", Value: "6"},
	}, &cfg.UnderlayFam, "4"); err != nil {
		return err
	}

	dev := defaultDev(cfg.UnderlayFam)
	if dev == "" {
		dev = "eth0"
	}
	if err := askInput(prompter, "Primary device", &dev, requireNonEmpty); err != nil {
		return err
	}
	cfg.Device = dev

	remote := ""
	if err := askInput(prompter, "Remote underlay IP", &remote, validateUnderlay(cfg.UnderlayFam)); err != nil {
		return err
	}
	cfg.RemoteUnder = remote

	local := ""
	_, src := routeSrcDev(cfg.UnderlayFam, remote)
	if src != "" {
		local = src
	}
	if err := askInput(prompter, "Local underlay IP", &local, validateUnderlay(cfg.UnderlayFam)); err != nil {
		return err
	}
	cfg.LocalUnder = local

	// Inner address
	insideEnv := strings.TrimSpace(os.Getenv("TUNNEL_INSIDE_ADDR"))
	if insideEnv != "" {
		innerCIDR, innerFam, err := parseTunnelInsideAddrEnv(insideEnv)
		if err != nil {
			return err
		}
		cfg.InnerFam = innerFam
		cfg.InnerCIDR = innerCIDR
		uiOut.Info("Inner address from TUNNEL_INSIDE_ADDR: " + cfg.InnerCIDR)
	} else {
		if err := askSelect(prompter, "Inner IP version", []ui.Option{
			{Label: "IPv4", Value: "4"},
			{Label: "IPv6", Value: "6"},
		}, &cfg.InnerFam, "4"); err != nil {
			return err
		}

		inner := ""
		if err := askInput(prompter, "Inner local address/CIDR", &inner, validateCIDR(cfg.InnerFam)); err != nil {
			return err
		}
		cfg.InnerCIDR = inner
	}

	// SPIs
	genSpi, err := askConfirm(prompter, "Generate new SPI pair? (Select 'No' if you are pasting from the other side)", true)
	if err != nil {
		return err
	}

	if genSpi {
		s1 := fmt.Sprintf("0x%x", cfg.IfID+0x1000)
		s2 := fmt.Sprintf("0x%x", cfg.IfID+0x2000)
		cfg.SpiIn = s1
		cfg.SpiOut = s2
		uiOut.Ok(fmt.Sprintf("Generated SPI Pair: %s,%s", s1, s2))
		uiOut.Dim("Please copy the string above and paste it on the remote side.")
	} else {
		spiInput := ""
		if err := askInput(prompter, "Paste SPI pair from remote (e.g. 0x1111,0x2222)", &spiInput, func(v string) error {
			parts := strings.Split(v, ",")
			if len(parts) != 2 {
				return errors.New("must provide two SPIs separated by comma")
			}
			return nil
		}); err != nil {
			return err
		}
		parts := strings.Split(spiInput, ",")
		cfg.SpiIn = parts[1]
		cfg.SpiOut = parts[0]
		uiOut.Info(fmt.Sprintf("Reversed SPIs for receiver: IN=%s, OUT=%s", cfg.SpiIn, cfg.SpiOut))
	}

	// Algo and Keys
	algoChoice := "1"
	if err := askSelectRaw(prompter, "Algorithm Profile", []ui.Option{
		{Label: "1) aes-gcm (128-bit) - Recommended", Value: "1"},
		{Label: "2) aes-cbc (256-bit) + hmac-sha256", Value: "2"},
	}, &algoChoice); err != nil {
		return err
	}

	genKeys, err := askConfirm(prompter, "Generate new Encryption Keys?", true)
	if err != nil {
		return err
	}

	if algoChoice == "1" {
		cfg.Algo = "aes-gcm"
		key := ""
		if genKeys {
			key, _ = generateRandomHex(20)
			uiOut.Ok("Generated GCM Key: " + key)
			uiOut.Dim("Please copy the key above to the remote side.")
		}
		if err := askInput(prompter, "Encryption Key (hex, 40 chars)", &key, validateHexLen(40)); err != nil {
			return err
		}
		cfg.EncKey = key
	} else {
		cfg.Algo = "aes-cbc-sha256"
		encKey := ""
		authKey := ""
		if genKeys {
			encKey, _ = generateRandomHex(32)
			authKey, _ = generateRandomHex(32)
			uiOut.Ok("Generated Enc Key: " + encKey)
			uiOut.Ok("Generated Auth Key: " + authKey)
			uiOut.Dim("Please copy the keys above to the remote side.")
		}

		if err := askInput(prompter, "Encryption Key (hex, 64 chars)", &encKey, validateHexLen(64)); err != nil {
			return err
		}
		cfg.EncKey = encKey

		if err := askInput(prompter, "Authentication Key (hex, 64 chars)", &authKey, validateHexLen(64)); err != nil {
			return err
		}
		cfg.AuthKey = authKey
	}

	return nil
}

func validateHex(v string) error {
	v = strings.TrimPrefix(v, "0x")
	_, err := hex.DecodeString(v)
	if err != nil {
		return errors.New("invalid hex format")
	}
	return nil
}

func validateHexLen(expected int) func(string) error {
	return func(v string) error {
		v = strings.TrimPrefix(v, "0x")
		if len(v) != expected {
			return fmt.Errorf("expected %d hex characters (found %d)", expected, len(v))
		}
		_, err := hex.DecodeString(v)
		if err != nil {
			return errors.New("invalid hex format")
		}
		return nil
	}
}

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func buildStaticXfrmIface(cfg *StaticXfrmConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Static XFRM Interface for %s\n", cfg.Name)
	fmt.Fprintf(&b, "auto %s\n", cfg.XfrmIf)
	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "iface %s inet6 manual\n", cfg.XfrmIf)
	} else {
		fmt.Fprintf(&b, "iface %s inet manual\n", cfg.XfrmIf)
	}

	// pre-up: create link
	fmt.Fprintf(&b, "    pre-up  ip link add %s type xfrm dev %s if_id %d || true\n", cfg.XfrmIf, cfg.Device, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip link set %s up\n", cfg.XfrmIf)

	// pre-up: add XFRM states (Manual Keying)
	if cfg.Algo == "aes-gcm" {
		// IN: remote -> local
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel aead 'rfc4106(aes)' 0x%s 128 if_id %d || true\n",
			cfg.RemoteUnder, cfg.LocalUnder, cfg.SpiIn, cfg.IfID, cfg.EncKey, cfg.IfID)
		// OUT: local -> remote
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel aead 'rfc4106(aes)' 0x%s 128 if_id %d || true\n",
			cfg.LocalUnder, cfg.RemoteUnder, cfg.SpiOut, cfg.IfID, cfg.EncKey, cfg.IfID)
	} else {
		// IN
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel enc 'cbc(aes)' 0x%s auth 'hmac(sha256)' 0x%s if_id %d || true\n",
			cfg.RemoteUnder, cfg.LocalUnder, cfg.SpiIn, cfg.IfID, cfg.EncKey, cfg.AuthKey, cfg.IfID)
		// OUT
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel enc 'cbc(aes)' 0x%s auth 'hmac(sha256)' 0x%s if_id %d || true\n",
			cfg.LocalUnder, cfg.RemoteUnder, cfg.SpiOut, cfg.IfID, cfg.EncKey, cfg.AuthKey, cfg.IfID)
	}

	// pre-up: add XFRM policies
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir in tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.RemoteUnder, cfg.LocalUnder, cfg.IfID, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src ::/0 dst ::/0 dir in tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.RemoteUnder, cfg.LocalUnder, cfg.IfID, cfg.IfID)

	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir out tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.LocalUnder, cfg.RemoteUnder, cfg.IfID, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src ::/0 dst ::/0 dir out tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.LocalUnder, cfg.RemoteUnder, cfg.IfID, cfg.IfID)

	// post-up: address
	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "    post-up ip -6 addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
	} else {
		fmt.Fprintf(&b, "    post-up ip addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
	}

	// down
	fmt.Fprintf(&b, "    down    ip link set %s down\n", cfg.XfrmIf)

	// post-down: cleanup
	fmt.Fprintf(&b, "    post-down ip xfrm state flush if_id %d || true\n", cfg.IfID)
	fmt.Fprintf(&b, "    post-down ip xfrm policy flush if_id %d || true\n", cfg.IfID)
	fmt.Fprintf(&b, "    post-down ip link del %s 2>/dev/null || true\n", cfg.XfrmIf)

	return b.String()
}

func printStaticXfrmNextSteps(cfg *StaticXfrmConfig, uiOut *ui.UI) {
	uiOut.HR()
	uiOut.Title("Configuration Summary (Manual Keying)")
	fmt.Fprintf(uiOut.Out, "  Interface: %s (if_id=%d)\n", cfg.XfrmIf, cfg.IfID)
	fmt.Fprintf(uiOut.Out, "  SPI IN: %s, SPI OUT: %s\n", cfg.SpiIn, cfg.SpiOut)
	fmt.Fprintf(uiOut.Out, "  Algo: %s\n", cfg.Algo)
	fmt.Fprintf(uiOut.Out, "  Enc Key: %s\n", cfg.EncKey)
	if cfg.AuthKey != "" {
		fmt.Fprintf(uiOut.Out, "  Auth Key: %s\n", cfg.AuthKey)
	}
	uiOut.HR()
	uiOut.Warn("Remote side needs SYMMETRIC configuration:")
	uiOut.Info("  - Swap Remote/Local underlay IPs")
	uiOut.Info("  - Use SAME SPI Pair (program will auto-reverse)")
	uiOut.Info("  - Use SAME Keys and Algorithm")
	uiOut.Info("  - Use SAME if_id: " + fmt.Sprint(cfg.IfID))
	uiOut.HR()
}
