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

type VxlanConfig struct {
	Name        string
	VNI         string
	UnderlayFam int
	Device      string
	RemoteUnder string
	LocalUnder  string
	InnerFam    int
	InnerCIDR   string
	MTU         string
	IfaceDir    string
	IfaceFile   string
}

func runVXLAN(uiOut *ui.UI, prompter *ui.Prompter) error {
	cfg := &VxlanConfig{
		IfaceDir: "/etc/network/interfaces.d",
	}

	uiOut.Title("VXLAN Tunnel Generator")

	name := "prod1"
	if err := askInput(prompter, "Tunnel name (interface: vxlan-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = "vxlan-" + name

	vni := "100"
	if err := askInput(prompter, "VXLAN ID (VNI)", &vni, func(v string) error {
		if !isDigits(v) {
			return errors.New("must be a number")
		}
		return nil
	}); err != nil {
		return err
	}
	cfg.VNI = vni

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
	if err := askInput(prompter, "Primary underlay device", &dev, validateDeviceName); err != nil {
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

	mtu := "1450"
	if err := askInput(prompter, "MTU (default 1450)", &mtu, validateNumber); err != nil {
		return err
	}
	if mtu == "" {
		mtu = "1450"
	}
	cfg.MTU = mtu

	cfg.IfaceFile = filepath.Join(cfg.IfaceDir, cfg.Name+".cfg")

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

	if err := os.MkdirAll(cfg.IfaceDir, 0700); err != nil {
		return err
	}

	iface := buildVxlanIface(cfg)
	if err := os.WriteFile(cfg.IfaceFile, []byte(iface), 0644); err != nil {
		return err
	}
	uiOut.Ok("wrote: " + cfg.IfaceFile)

	if err := ensureInterfacesSource(uiOut, prompter); err != nil {
		return err
	}

	uiOut.Info("Bringing up interface " + cfg.Name + "...")
	if err := sys.Run("ifup", cfg.Name); err != nil {
		uiOut.Warn("Failed to bring up interface. Is it already up?")
	} else {
		uiOut.Ok("Interface is up")
	}

	uiOut.HR()
	uiOut.Title("Next steps")
	fmt.Fprintf(uiOut.Out, "  ip -d link show %s\n", cfg.Name)
	fmt.Fprintf(uiOut.Out, "  ping <remote-inner-ip> -I %s\n", cfg.Name)
	uiOut.HR()

	return nil
}

func buildVxlanIface(cfg *VxlanConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VXLAN Interface %s (VNI %s)\n", cfg.Name, cfg.VNI)
	fmt.Fprintf(&b, "auto %s\n", cfg.Name)
	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "iface %s inet6 manual\n", cfg.Name)
	} else {
		fmt.Fprintf(&b, "iface %s inet manual\n", cfg.Name)
	}

	fmt.Fprintf(&b, "    pre-up  ip link add %s type vxlan id %s local %s remote %s dstport 4789 dev %s || true\n", cfg.Name, cfg.VNI, cfg.LocalUnder, cfg.RemoteUnder, cfg.Device)
	fmt.Fprintf(&b, "    pre-up  ip link set %s up mtu %s\n", cfg.Name, cfg.MTU)

	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "    post-up ip -6 addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.Name)
		fmt.Fprintf(&b, "    pre-down ip -6 addr del %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.Name)
	} else {
		fmt.Fprintf(&b, "    post-up ip addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.Name)
		fmt.Fprintf(&b, "    pre-down ip addr del %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.Name)
	}
	fmt.Fprintf(&b, "    down    ip link set %s down\n", cfg.Name)
	fmt.Fprintf(&b, "    post-down ip link del %s 2>/dev/null || true\n", cfg.Name)
	return b.String()
}
