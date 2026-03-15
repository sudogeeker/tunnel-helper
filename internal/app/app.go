package app

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"go-xfrm/internal/sys"
	"go-xfrm/internal/ui"
)

var ErrAborted = errors.New("aborted")

type Config struct {
	UnderlayFam int
	Device      string
	RemoteUnder string
	LocalUnder  string
	RemoteID    string
	LocalID     string
	Name        string
	XfrmIf      string
	IfID        int
	InnerFam    int
	InnerCIDR   string
	PSK         string
	IkeAlg      string
	EspAlg      string
	Encap       bool
	Keepalive   string
	ConfDir     string
	SwanctlDir  string
	IfaceDir    string
	ConnFile    string
	SecretsFile string
	IfaceFile   string
	DefaultDev  string
	RouteDev    string
	RouteSrc    string
}

func Run(args []string) error {
	fs := flag.NewFlagSet("xfrmgen", flag.ContinueOnError)
	confDir := fs.String("confdir", "/etc/swanctl/conf.d", "swanctl config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	uiOut := ui.New(os.Stdout, os.Stderr, os.Stdin)
	prompter := ui.NewPrompter(uiOut)

	if runtimeWarn := runtimeCheck(); runtimeWarn != nil {
		uiOut.Warn(runtimeWarn.Error())
	}

	if !sys.IsRoot() {
		return errors.New("run as root (sudo -i)")
	}

	if err := requireCommands(uiOut, "ip"); err != nil {
		return err
	}

	if err := wrapAbort(checkXFRMSupport(uiOut)); err != nil {
		return err
	}

	if err := wrapAbort(ensurePackages(uiOut, prompter)); err != nil {
		return err
	}

	if err := wrapAbort(ensureSwanctl(uiOut)); err != nil {
		return err
	}

	checkStrongSwanService(uiOut)

	cfg := &Config{}
	cfg.ConfDir = *confDir
	cfg.SwanctlDir = "/etc/swanctl"
	cfg.IfaceDir = "/etc/network/interfaces.d"

	uiOut.HR()
	uiOut.Title("XFRM Interface + strongSwan (swanctl) Generator")
	uiOut.Dim("XFRM interface + PFS rotation")
	uiOut.HR()

	if err := wrapAbort(collectInputs(cfg, uiOut, prompter)); err != nil {
		return err
	}

	if err := wrapAbort(computePaths(cfg)); err != nil {
		return err
	}

	if err := wrapAbort(writeFiles(cfg, uiOut, prompter)); err != nil {
		return err
	}

	if err := wrapAbort(ensureSwanctlConf(cfg, uiOut, prompter)); err != nil {
		return err
	}

	if err := wrapAbort(ensureInterfacesSource(uiOut, prompter)); err != nil {
		return err
	}

	printNextSteps(cfg, uiOut)
	return nil
}

func runtimeCheck() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this tool is intended for Linux; current GOOS=%s", runtime.GOOS)
	}
	return nil
}

func isAbortErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, huh.ErrUserAborted)
}

func wrapAbort(err error) error {
	if err == nil {
		return nil
	}
	if isAbortErr(err) {
		return ErrAborted
	}
	return err
}

func requireCommands(uiOut *ui.UI, names ...string) error {
	for _, name := range names {
		if !sys.LookPath(name) {
			return fmt.Errorf("missing command: %s", name)
		}
	}
	return nil
}

func checkXFRMSupport(uiOut *ui.UI) error {
	if _, err := os.Stat("/proc/net/xfrm_stat"); err != nil {
		uiOut.Warn("kernel may not support XFRM; check xfrm modules")
	}
	return nil
}

func ensurePackages(uiOut *ui.UI, prompter *ui.Prompter) error {
	if !sys.LookPath("dpkg-query") {
		uiOut.Warn("dpkg-query not found; skipping package check")
		return nil
	}

	required := []string{
		"charon-systemd",
		"strongswan-swanctl",
		"strongswan-libcharon",
		"libstrongswan-standard-plugins",
		"libstrongswan-extra-plugins",
		"libcharon-extra-plugins",
	}

	missing := make([]string, 0)
	for _, pkg := range required {
		out, err := sys.Output("dpkg-query", "-W", "-f=${Status}", pkg)
		if err != nil || !strings.Contains(out, "install ok installed") {
			missing = append(missing, pkg)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	uiOut.Warn("missing required packages:")
	for _, pkg := range missing {
		uiOut.Warn("  - " + pkg)
	}

	ok, err := askConfirm(prompter, "Install missing packages now?", false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("missing required packages; install them and rerun")
	}
	if !sys.LookPath("apt") {
		return errors.New("apt not found; install packages manually")
	}

	uiOut.Info("running apt update...")
	if err := sys.Run("apt", "update"); err != nil {
		return fmt.Errorf("apt update failed: %w", err)
	}
	uiOut.Info("installing packages...")
	args := append([]string{"install", "-y"}, missing...)
	if err := sys.Run("apt", args...); err != nil {
		return fmt.Errorf("apt install failed: %w", err)
	}
	uiOut.Ok("packages installed")
	return nil
}

func ensureSwanctl(uiOut *ui.UI) error {
	if !sys.LookPath("swanctl") {
		return errors.New("swanctl not found; check installation")
	}
	return nil
}

func checkStrongSwanService(uiOut *ui.UI) {
	if !sys.LookPath("systemctl") {
		uiOut.Warn("systemctl not found; skipping service check")
		return
	}
	if err := sys.Run("systemctl", "is-active", "--quiet", "strongswan"); err == nil {
		uiOut.Info("strongSwan service is running")
		return
	}
	out, err := sys.Output("systemctl", "list-unit-files")
	if err != nil {
		uiOut.Warn("could not query systemd unit files")
		return
	}
	if strings.Contains(out, "strongswan.service") {
		uiOut.Warn("strongSwan is installed but not running")
		return
	}
	uiOut.Warn("strongswan.service not found; check charon-systemd installation")
}

func collectInputs(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	if err := askSelect(prompter, "Underlay IP version", []ui.Option{
		{Label: "IPv4", Value: "4"},
		{Label: "IPv6", Value: "6"},
	}, &cfg.UnderlayFam, "6"); err != nil {
		return err
	}

	cfg.DefaultDev = defaultDev(cfg.UnderlayFam)
	if cfg.DefaultDev == "" {
		cfg.DefaultDev = "eth0"
	}

	dev := cfg.DefaultDev
	if err := askInput(prompter, "Primary interface for XFRM dev", &dev, func(v string) error {
		if strings.TrimSpace(v) == "" {
			return errors.New("device is required")
		}
		return nil
	}); err != nil {
		return err
	}
	cfg.Device = dev

	remote := ""
	if err := askInput(prompter, "Remote underlay IP (or %any)", &remote, validateUnderlay(cfg.UnderlayFam)); err != nil {
		return err
	}
	cfg.RemoteUnder = normalizeAny(remote)

	if cfg.RemoteUnder != "%any" {
		cfg.RouteDev, cfg.RouteSrc = routeSrcDev(cfg.UnderlayFam, cfg.RemoteUnder)
	}
	if cfg.RouteDev == "" {
		cfg.RouteDev = cfg.Device
	}

	if cfg.RouteSrc == "" {
		uiOut.Warn("could not detect local source IP; you must enter it")
	}

	local := cfg.RouteSrc
	if err := askInput(prompter, "Local underlay IP (or %any)", &local, validateUnderlay(cfg.UnderlayFam)); err != nil {
		return err
	}
	cfg.LocalUnder = normalizeAny(local)

	localID := cfg.LocalUnder
	remoteID := cfg.RemoteUnder
	if err := askInput(prompter, "Local ID", &localID, requireNonEmpty); err != nil {
		return err
	}
	if err := askInput(prompter, "Remote ID", &remoteID, requireNonEmpty); err != nil {
		return err
	}
	cfg.LocalID = localID
	cfg.RemoteID = remoteID

	name := "prod1"
	if err := askInput(prompter, "Tunnel name (interface: ipsec-<name>)", &name, validateName); err != nil {
		return err
	}
	cfg.Name = name
	cfg.XfrmIf = "ipsec-" + name
	cfg.IfID = generateIfID(name)
	uiOut.Info(fmt.Sprintf("generated if_id: %d", cfg.IfID))

	if used := isIfIDUsed(cfg.IfID); used {
		uiOut.Warn(fmt.Sprintf("if_id %d already in use", cfg.IfID))
		ok, err := askConfirm(prompter, "Continue anyway?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled by user")
		}
	}

	if err := askSelect(prompter, "Inner IP version", []ui.Option{
		{Label: "IPv4", Value: "4"},
		{Label: "IPv6", Value: "6"},
	}, &cfg.InnerFam, "6"); err != nil {
		return err
	}

	innerDefault := "fd00:cafe::0/127"
	if cfg.InnerFam == 4 {
		innerDefault = "10.255.255.0/31"
	}
	innerCIDR := innerDefault
	if err := askInput(prompter, "Inner local address/CIDR", &innerCIDR, validateCIDR(cfg.InnerFam)); err != nil {
		return err
	}
	cfg.InnerCIDR = innerCIDR

	psk := ""
	if err := askInput(prompter, "PSK (leave blank to auto-generate)", &psk, nil); err != nil {
		return err
	}
	if strings.TrimSpace(psk) == "" {
		gen, err := generatePSK()
		if err != nil {
			return err
		}
		psk = gen
		uiOut.Ok("generated PSK: " + psk)
	}
	cfg.PSK = psk

	algoChoice := "1"
	if err := askSelectRaw(prompter, "Algorithm profile", []ui.Option{
		{Label: "1) aes128gcm16-prfsha256-modp2048 (recommended)", Value: "1"},
		{Label: "2) aes256gcm16-prfsha256-ecp256 (ECC)", Value: "2"},
		{Label: "3) aes256gcm16-prfsha384-modp3072 (high security)", Value: "3"},
	}, &algoChoice); err != nil {
		return err
	}

	switch algoChoice {
	case "1":
		cfg.IkeAlg = "aes128gcm16-prfsha256-modp2048"
		cfg.EspAlg = "aes128gcm16"
	case "2":
		cfg.IkeAlg = "aes256gcm16-prfsha256-ecp256"
		cfg.EspAlg = "aes256gcm16"
	case "3":
		cfg.IkeAlg = "aes256gcm16-prfsha384-modp3072"
		cfg.EspAlg = "aes256gcm16"
	default:
		return fmt.Errorf("invalid algorithm choice: %s", algoChoice)
	}

	uiOut.Info("IKE lifetime: 1h, Child SA lifetime: 8h (adjust in config if needed)")

	encap, err := askConfirm(prompter, "Enable encap = yes?", false)
	if err != nil {
		return err
	}
	cfg.Encap = encap

	keepalive := ""
	if err := askInput(prompter, "Keepalive (e.g. 20s, leave blank to skip)", &keepalive, validateKeepalive); err != nil {
		return err
	}
	keepalive, err = normalizeKeepalive(keepalive)
	if err != nil {
		return err
	}
	cfg.Keepalive = keepalive

	return nil
}

func askSelect(prompter *ui.Prompter, title string, options []ui.Option, target *int, def string) error {
	val := def
	if err := askSelectRaw(prompter, title, options, &val); err != nil {
		return err
	}
	if val == "4" {
		*target = 4
		return nil
	}
	if val == "6" {
		*target = 6
		return nil
	}
	return fmt.Errorf("invalid selection: %s", val)
}

func askSelectRaw(prompter *ui.Prompter, title string, options []ui.Option, target *string) error {
	for {
		if err := prompter.Select(title, options, target); err == nil {
			return nil
		} else if isAbortErr(err) {
			return err
		}
	}
}

func askInput(prompter *ui.Prompter, title string, target *string, validate func(string) error) error {
	for {
		if err := prompter.Input(title, target, validate); err == nil {
			return nil
		} else if isAbortErr(err) {
			return err
		}
	}
}

func askConfirm(prompter *ui.Prompter, title string, defaultYes bool) (bool, error) {
	for {
		val := defaultYes
		if err := prompter.Confirm(title, &val, defaultYes); err == nil {
			return val, nil
		} else if isAbortErr(err) {
			return false, err
		}
	}
}

func validateUnderlay(fam int) func(string) error {
	return func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return errors.New("value is required")
		}
		if isAny(value) {
			return nil
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return errors.New("invalid IP address")
		}
		if fam == 4 && ip.To4() == nil {
			return errors.New("expected IPv4 address")
		}
		if fam == 6 && ip.To4() != nil {
			return errors.New("expected IPv6 address")
		}
		return nil
	}
}

func validateCIDR(fam int) func(string) error {
	return func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return errors.New("CIDR is required")
		}
		ip, _, err := net.ParseCIDR(value)
		if err != nil {
			return errors.New("invalid CIDR")
		}
		if fam == 4 && ip.To4() == nil {
			return errors.New("expected IPv4 CIDR")
		}
		if fam == 6 && ip.To4() != nil {
			return errors.New("expected IPv6 CIDR")
		}
		return nil
	}
}

func validateName(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("name is required")
	}
	ok, _ := regexp.MatchString("^[a-zA-Z0-9._-]+$", value)
	if !ok {
		return errors.New("allowed characters: a-zA-Z0-9 . _ -")
	}
	return nil
}

func requireNonEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value is required")
	}
	return nil
}

func validateKeepalive(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	_, err := normalizeKeepalive(value)
	return err
}

func normalizeKeepalive(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if isDigits(value) {
		value = value + "s"
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return "", errors.New("invalid duration")
	}
	if d <= 0 {
		return "", errors.New("keepalive must be positive")
	}
	return value, nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func isAny(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "%any")
}

func normalizeAny(s string) string {
	if isAny(s) {
		return "%any"
	}
	return strings.TrimSpace(s)
}

func defaultDev(fam int) string {
	args := []string{"-4", "route", "show", "default"}
	if fam == 6 {
		args = []string{"-6", "route", "show", "default"}
	}
	out, err := sys.Output("ip", args...)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func routeSrcDev(fam int, remote string) (string, string) {
	args := []string{"-4", "route", "get", remote}
	if fam == 6 {
		args = []string{"-6", "route", "get", remote}
	}
	out, err := sys.Output("ip", args...)
	if err != nil {
		return "", ""
	}
	dev := ""
	src := ""
	fields := strings.Fields(out)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
		if fields[i] == "src" {
			src = fields[i+1]
		}
	}
	return dev, src
}

func generateIfID(name string) int {
	hash := md5.Sum([]byte(name))
	hexStr := hex.EncodeToString(hash[:])
	if len(hexStr) < 4 {
		return 1
	}
	v, err := strconv.ParseInt(hexStr[:4], 16, 64)
	if err != nil {
		return 1
	}
	return int(v%65535) + 1
}

func isIfIDUsed(id int) bool {
	out, err := sys.Output("ip", "link", "show", "type", "xfrm")
	if err != nil {
		return false
	}
	needle := fmt.Sprintf("if_id %d", id)
	return strings.Contains(out, needle)
}

func generatePSK() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func computePaths(cfg *Config) error {
	cfg.ConnFile = filepath.Join(cfg.ConfDir, cfg.XfrmIf+".conf")
	cfg.SecretsFile = filepath.Join(cfg.SwanctlDir, "conf.d", cfg.XfrmIf+".secrets")
	cfg.IfaceFile = filepath.Join(cfg.IfaceDir, cfg.XfrmIf+".cfg")
	return nil
}

func writeFiles(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	if err := os.MkdirAll(cfg.ConfDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.IfaceDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(cfg.SwanctlDir, "conf.d"), 0755); err != nil {
		return err
	}

	exists := []string{}
	for _, path := range []string{cfg.ConnFile, cfg.SecretsFile, cfg.IfaceFile} {
		if _, err := os.Stat(path); err == nil {
			exists = append(exists, path)
		}
	}

	if len(exists) > 0 {
		uiOut.Warn("the following files already exist:")
		for _, path := range exists {
			uiOut.Warn("  - " + path)
		}
		overwrite, err := askConfirm(prompter, "Overwrite existing files?", false)
		if err != nil {
			return err
		}
		if !overwrite {
			return errors.New("cancelled; delete or rename existing files")
		}
	}

	conn := buildConn(cfg)
	secrets := buildSecrets(cfg)
	iface := buildIface(cfg)

	if err := os.WriteFile(cfg.ConnFile, []byte(conn), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.SecretsFile, []byte(secrets), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.IfaceFile, []byte(iface), 0644); err != nil {
		return err
	}

	uiOut.Ok("wrote: " + cfg.ConnFile)
	uiOut.Ok("wrote: " + cfg.SecretsFile)
	uiOut.Ok("wrote: " + cfg.IfaceFile)
	return nil
}

func buildConn(cfg *Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by xfrmgen\n")
	fmt.Fprintf(&b, "# XFRM Interface: %s (if_id=%d)\n", cfg.XfrmIf, cfg.IfID)
	fmt.Fprintf(&b, "# Underlay: %s <-> %s\n", cfg.LocalUnder, cfg.RemoteUnder)
	fmt.Fprintf(&b, "# Inner: %s\n\n", cfg.InnerCIDR)
	b.WriteString("connections {\n")
	fmt.Fprintf(&b, "    %s {\n", cfg.Name)
	b.WriteString("        version = 2\n")
	fmt.Fprintf(&b, "        local_addrs = %s\n", cfg.LocalUnder)
	fmt.Fprintf(&b, "        remote_addrs = %s\n\n", cfg.RemoteUnder)
	b.WriteString("        local {\n")
	b.WriteString("            auth = psk\n")
	fmt.Fprintf(&b, "            id = %s\n", cfg.LocalID)
	b.WriteString("        }\n")
	b.WriteString("        remote {\n")
	b.WriteString("            auth = psk\n")
	fmt.Fprintf(&b, "            id = %s\n", cfg.RemoteID)
	b.WriteString("        }\n\n")
	b.WriteString("        children {\n")
	fmt.Fprintf(&b, "            %s-child {\n", cfg.Name)
	b.WriteString("                mode = tunnel\n")
	b.WriteString("                local_ts = 0.0.0.0/0,::/0\n")
	b.WriteString("                remote_ts = 0.0.0.0/0,::/0\n\n")
	fmt.Fprintf(&b, "                if_id_in = %d\n", cfg.IfID)
	fmt.Fprintf(&b, "                if_id_out = %d\n\n", cfg.IfID)
	b.WriteString("                start_action = start\n")
	b.WriteString("                close_action = trap\n\n")
	fmt.Fprintf(&b, "                esp_proposals = %s\n", cfg.EspAlg)
	b.WriteString("                rekey_time = 8h\n")
	b.WriteString("                life_time = 10h\n")
	b.WriteString("                dpd_action = restart\n")
	if cfg.Encap {
		b.WriteString("                encap = yes\n")
	}
	if cfg.Keepalive != "" {
		fmt.Fprintf(&b, "                keepalive = %s\n", cfg.Keepalive)
	}
	b.WriteString("            }\n")
	b.WriteString("        }\n\n")
	fmt.Fprintf(&b, "        proposals = %s\n", cfg.IkeAlg)
	b.WriteString("        rekey_time = 1h\n")
	b.WriteString("        over_time = 90m\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        dpd_timeout = 150s\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func buildSecrets(cfg *Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PSK for %s\n", cfg.Name)
	b.WriteString("secrets {\n")
	fmt.Fprintf(&b, "    ike-%s {\n", cfg.Name)
	fmt.Fprintf(&b, "        id-local = %s\n", cfg.LocalID)
	fmt.Fprintf(&b, "        id-remote = %s\n", cfg.RemoteID)
	fmt.Fprintf(&b, "        secret = \"%s\"\n", cfg.PSK)
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func buildIface(cfg *Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# XFRM Interface for %s\n", cfg.Name)
	fmt.Fprintf(&b, "auto %s\n", cfg.XfrmIf)
	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "iface %s inet6 manual\n", cfg.XfrmIf)
	} else {
		fmt.Fprintf(&b, "iface %s inet manual\n", cfg.XfrmIf)
	}
	fmt.Fprintf(&b, "    pre-up  ip link add %s type xfrm dev %s if_id %d || true\n", cfg.XfrmIf, cfg.Device, cfg.IfID)
	fmt.Fprintf(&b, "    pre-up  ip link set %s multicast on up\n", cfg.XfrmIf)
	if cfg.InnerFam == 6 {
		fmt.Fprintf(&b, "    post-up ip -6 addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
		fmt.Fprintf(&b, "    pre-down ip -6 addr del %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
	} else {
		fmt.Fprintf(&b, "    post-up ip addr replace %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
		fmt.Fprintf(&b, "    pre-down ip addr del %s dev %s 2>/dev/null || true\n", cfg.InnerCIDR, cfg.XfrmIf)
	}
	fmt.Fprintf(&b, "    down    ip link set %s down\n", cfg.XfrmIf)
	fmt.Fprintf(&b, "    post-down ip link del %s 2>/dev/null || true\n", cfg.XfrmIf)
	return b.String()
}

func ensureSwanctlConf(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	path := filepath.Join(cfg.SwanctlDir, "swanctl.conf")
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	text := string(content)

	if strings.Contains(text, "include conf.d/*.conf") == false && text != "" {
		uiOut.Warn("swanctl.conf does not include conf.d/*.conf")
		ok, err := askConfirm(prompter, "Append include line?", false)
		if err != nil {
			return err
		}
		if ok {
			text = text + "\n# Include connection configs\ninclude conf.d/*.conf\n"
			if err := os.WriteFile(path, []byte(text), 0644); err != nil {
				return err
			}
			uiOut.Ok("appended include to swanctl.conf")
		}
	}

	if !strings.Contains(text, "include conf.d/*.secrets") {
		if text == "" {
			text = "# Main swanctl config\ninclude conf.d/*.conf\ninclude conf.d/*.secrets\n"
		} else {
			text = text + "\n# Include secrets\ninclude conf.d/*.secrets\n"
		}
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			return err
		}
		uiOut.Ok("ensured secrets include in swanctl.conf")
	}

	return nil
}

func ensureInterfacesSource(uiOut *ui.UI, prompter *ui.Prompter) error {
	path := "/etc/network/interfaces"
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text := string(content)
	if strings.Contains(text, "source /etc/network/interfaces.d/*") {
		return nil
	}
	uiOut.Warn("/etc/network/interfaces missing source /etc/network/interfaces.d/*")
	ok, err := askConfirm(prompter, "Append source line?", false)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	text = text + "\nsource /etc/network/interfaces.d/*\n"
	return os.WriteFile(path, []byte(text), 0644)
}

func printNextSteps(cfg *Config, uiOut *ui.UI) {
	uiOut.HR()
	uiOut.Title("Next steps")
	fmt.Fprintf(uiOut.Out, "  systemctl enable --now strongswan\n")
	fmt.Fprintf(uiOut.Out, "  swanctl --load-all\n")
	fmt.Fprintf(uiOut.Out, "  ifup %s\n", cfg.XfrmIf)
	fmt.Fprintf(uiOut.Out, "  swanctl --list-conns\n")
	fmt.Fprintf(uiOut.Out, "  swanctl --list-sas\n")
	fmt.Fprintf(uiOut.Out, "  ip link show %s\n", cfg.XfrmIf)
	fmt.Fprintf(uiOut.Out, "  ip addr show %s\n", cfg.XfrmIf)
	fmt.Fprintf(uiOut.Out, "  ping <remote-inner-ip> -I %s\n", cfg.XfrmIf)
	uiOut.HR()
	uiOut.Warn("Remote side needs:")
	fmt.Fprintf(uiOut.Out, "  - Same PSK (see %s)\n", cfg.SecretsFile)
	fmt.Fprintf(uiOut.Out, "  - Symmetric underlay IPs\n")
	fmt.Fprintf(uiOut.Out, "  - Same if_id: %d (recommended)\n", cfg.IfID)
	fmt.Fprintf(uiOut.Out, "  - Symmetric inner IPs (/127 or /31)\n")
	uiOut.HR()
	uiOut.Info("PFS note: DH group is encoded in the IKE proposal (modp/ecp)")
	uiOut.Info("Rekey performs a fresh DH exchange for PFS")
	uiOut.HR()
}
