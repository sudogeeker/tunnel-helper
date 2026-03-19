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
	MTU         string

	// Manual Keying (Directional)
	SpiIn      string
	SpiOut     string
	EncKeyIn   string
	EncKeyOut  string
	AuthKeyIn  string
	AuthKeyOut string
	Algo       string
}

func runStaticXFRM(uiOut *ui.UI, prompter *ui.Prompter) error {
	uiOut.Clear()
	cfg := &StaticXfrmConfig{
		IfaceDir: "/etc/network/interfaces.d",
	}

	uiOut.Title("XFRM with Static Keys")
	uiOut.Dim("No IKE negotiation, no 500/4500 UDP needed")

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
	if err := askInput(prompter, "Primary device", &dev, validateDeviceName); err != nil {
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

	// MTU
	mtu := "1400"
	if err := askInput(prompter, "Interface MTU (default 1400)", &mtu, func(v string) error {
		if v != "" && !isDigits(v) {
			return errors.New("must be a number")
		}
		return nil
	}); err != nil {
		return err
	}
	if mtu == "" {
		mtu = "1400"
	}
	cfg.MTU = mtu

	// SPIs
	genSpi, err := askConfirm(prompter, "Generate new SPI pair?", true)
	if err != nil {
		return err
	}

	if genSpi {
		s1 := fmt.Sprintf("0x%x", cfg.IfID+0x1000)
		s2 := fmt.Sprintf("0x%x", cfg.IfID+0x2000)
		cfg.SpiIn = s1
		cfg.SpiOut = s2
		uiOut.Ok(fmt.Sprintf("Generated SPI Pair (IN,OUT): %s,%s", s1, s2))
	} else {
		spiInput := ""
		if err := askInput(prompter, "Paste SPI pair from remote (e.g. IN,OUT)", &spiInput, func(v string) error {
			if len(strings.Split(v, ",")) != 2 {
				return errors.New("format: SPI_IN,SPI_OUT")
			}
			return nil
		}); err != nil {
			return err
		}
		parts := strings.Split(spiInput, ",")
		// Auto reverse
		cfg.SpiIn = strings.TrimSpace(parts[1])
		cfg.SpiOut = strings.TrimSpace(parts[0])
		uiOut.Info(fmt.Sprintf("Reversed SPIs: IN=%s, OUT=%s", cfg.SpiIn, cfg.SpiOut))
	}

	// Algo Choice
	algoChoice := "1"
	if err := askSelectRaw(prompter, "Algorithm Profile", []ui.Option{
		{Label: "1) aes-gcm (128-bit) - Recommended", Value: "1"},
		{Label: "2) aes-cbc (256-bit) + hmac-sha256", Value: "2"},
	}, &algoChoice); err != nil {
		return err
	}

	genKeys, err := askConfirm(prompter, "Generate new Key pair?", true)
	if err != nil {
		return err
	}

	if algoChoice == "1" {
		cfg.Algo = "aes-gcm"
		keyInput := ""
		if genKeys {
			k1, _ := generateRandomHex(20)
			k2, _ := generateRandomHex(20)
			keyInput = k1 + "," + k2
			uiOut.Ok("Generated Key Pair (IN,OUT): " + keyInput)
		}
		if err := askInput(prompter, "Paste Key Pair (e.g. K1,K2)", &keyInput, func(v string) error {
			if len(strings.Split(v, ",")) != 2 {
				return errors.New("format: KEY_IN,KEY_OUT")
			}
			return nil
		}); err != nil {
			return err
		}
		parts := strings.Split(keyInput, ",")
		if genKeys {
			cfg.EncKeyIn = strings.TrimSpace(parts[0])
			cfg.EncKeyOut = strings.TrimSpace(parts[1])
		} else {
			// Reverse for pasting
			cfg.EncKeyIn = strings.TrimSpace(parts[1])
			cfg.EncKeyOut = strings.TrimSpace(parts[0])
			uiOut.Info("Keys reversed for receiver side.")
		}
	} else {
		cfg.Algo = "aes-cbc-sha256"
		// This needs two sets of keys (Enc and Auth)
		// For simplicity, we ask for Enc Pair and Auth Pair separately
		encPair := ""
		if genKeys {
			k1, _ := generateRandomHex(32)
			k2, _ := generateRandomHex(32)
			encPair = k1 + "," + k2
			uiOut.Ok("Generated Enc Key Pair: " + encPair)
		}
		err := askInput(prompter, "Paste Enc Key Pair", &encPair, func(v string) error {
			if len(strings.Split(v, ",")) != 2 {
				return errors.New("format: KEY_IN,KEY_OUT")
			}
			return nil
		})
		if err != nil {
			return err
		}
		parts := strings.Split(encPair, ",")
		if genKeys {
			cfg.EncKeyIn = strings.TrimSpace(parts[0])
			cfg.EncKeyOut = strings.TrimSpace(parts[1])
		} else {
			cfg.EncKeyIn = strings.TrimSpace(parts[1])
			cfg.EncKeyOut = strings.TrimSpace(parts[0])
		}

		authPair := ""
		if genKeys {
			k1, _ := generateRandomHex(32)
			k2, _ := generateRandomHex(32)
			authPair = k1 + "," + k2
			uiOut.Ok("Generated Auth Key Pair: " + authPair)
		}
		err = askInput(prompter, "Paste Auth Key Pair", &authPair, func(v string) error {
			if len(strings.Split(v, ",")) != 2 {
				return errors.New("format: KEY_IN,KEY_OUT")
			}
			return nil
		})
		if err != nil {
			return err
		}
		partsAuth := strings.Split(authPair, ",")
		if genKeys {
			cfg.AuthKeyIn = strings.TrimSpace(partsAuth[0])
			cfg.AuthKeyOut = strings.TrimSpace(partsAuth[1])
		} else {
			cfg.AuthKeyIn = strings.TrimSpace(partsAuth[1])
			cfg.AuthKeyOut = strings.TrimSpace(partsAuth[0])
		}
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
	fmt.Fprintf(&b, "    mtu %s\n", cfg.MTU)

	// pre-up: create link
	fmt.Fprintf(&b, "    pre-up  ip link add %s type xfrm dev %s if_id %d || true\n", cfg.XfrmIf, cfg.Device, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip link set %s up\n", cfg.XfrmIf)

	// pre-up: add XFRM states (Manual Keying with Directional Keys)
	if cfg.Algo == "aes-gcm" {
		// IN: remote -> local (use EncKeyIn)
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel aead 'rfc4106(gcm(aes))' 0x%s 128 if_id %d flag af-unspec || true\n",
			cfg.RemoteUnder, cfg.LocalUnder, cfg.SpiIn, cfg.IfID, cfg.EncKeyIn, cfg.IfID)
		// OUT: local -> remote (use EncKeyOut)
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel aead 'rfc4106(gcm(aes))' 0x%s 128 if_id %d flag af-unspec || true\n",
			cfg.LocalUnder, cfg.RemoteUnder, cfg.SpiOut, cfg.IfID, cfg.EncKeyOut, cfg.IfID)
	} else {
		// IN
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel enc 'cbc(aes)' 0x%s auth 'hmac(sha256)' 0x%s if_id %d flag af-unspec || true\n",
			cfg.RemoteUnder, cfg.LocalUnder, cfg.SpiIn, cfg.IfID, cfg.EncKeyIn, cfg.AuthKeyIn, cfg.IfID)
		// OUT
		fmt.Fprintf(&b, "    pre-up  ip xfrm state add src %s dst %s proto esp spi %s reqid %d mode tunnel enc 'cbc(aes)' 0x%s auth 'hmac(sha256)' 0x%s if_id %d flag af-unspec || true\n",
			cfg.LocalUnder, cfg.RemoteUnder, cfg.SpiOut, cfg.IfID, cfg.EncKeyOut, cfg.AuthKeyOut, cfg.IfID)
	}

	// pre-up: add XFRM policies
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir in tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.RemoteUnder, cfg.LocalUnder, cfg.IfID, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src ::/0 dst ::/0 dir in tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.RemoteUnder, cfg.LocalUnder, cfg.IfID, cfg.IfID)

	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src 0.0.0.0/0 dst 0.0.0.0/0 dir fwd tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
		cfg.RemoteUnder, cfg.LocalUnder, cfg.IfID, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip xfrm policy add src ::/0 dst ::/0 dir fwd tmpl src %s dst %s proto esp reqid %d mode tunnel if_id %d || true\n",
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
	fmt.Fprintf(uiOut.Out, "  Enc Key IN:  %s\n", cfg.EncKeyIn)
	fmt.Fprintf(uiOut.Out, "  Enc Key OUT: %s\n", cfg.EncKeyOut)
	if cfg.AuthKeyIn != "" {
		fmt.Fprintf(uiOut.Out, "  Auth Key IN:  %s\n", cfg.AuthKeyIn)
		fmt.Fprintf(uiOut.Out, "  Auth Key OUT: %s\n", cfg.AuthKeyOut)
	}
	uiOut.HR()
	uiOut.Warn("Remote side needs SYMMETRIC configuration:")
	uiOut.Info("  - Swap Remote/Local underlay IPs")
	uiOut.Info("  - Use SAME SPI Pair (system will auto-reverse)")
	uiOut.Info("  - Use SAME Key Pairs (system will auto-reverse)")
	uiOut.Info("  - Use SAME if_id: " + fmt.Sprint(cfg.IfID))
	uiOut.HR()
}
