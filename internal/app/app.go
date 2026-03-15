package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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

	"github.com/charmbracelet/huh"

	"github.com/sudogeeker/go-xfrm/internal/sys"
	"github.com/sudogeeker/go-xfrm/internal/ui"
)

var ErrAborted = errors.New("aborted")

type Config struct {
	UnderlayFam      int
	Device           string
	RemoteUnder      string
	LocalUnder       string
	RemoteID         string
	LocalID          string
	Name             string
	XfrmIf           string
	IfID             int
	InnerFam         int
	InnerCIDR        string
	AuthMethod       string
	PSK              string
	KexGroup         string
	RPKAlgo          string
	RPKLocalKey      string
	RPKRemoteKey     string
	RPKLocalPrivFile string
	RPKLocalPubFile  string
	RPKRemotePubFile string
	RPKLocalPubDER   []byte
	RPKRemotePubDER  []byte
	IkeAlg           string
	EspAlg           string
	Encap            bool
	StartAction      string
	ConfDir          string
	SwanctlDir       string
	IfaceDir         string
	ConnFile         string
	SecretsFile      string
	IfaceFile        string
	DefaultDev       string
	RouteDev         string
	RouteSrc         string
}

const (
	AuthPSK = "psk"
	AuthRPK = "rpk"

	RPKAlgoP256    = "p256"
	RPKAlgoP384    = "p384"
	RPKAlgoP521    = "p521"
	RPKAlgoEd25519 = "ed25519"
)

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

	if err := wrapAbort(checkNetworkingMode(uiOut)); err != nil {
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

	printConfigSummary(cfg, uiOut)

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

func checkNetworkingMode(uiOut *ui.UI) error {
	if !sys.LookPath("ifup") {
		return errors.New("ifupdown not detected (ifup missing); this tool requires /etc/network/interfaces, netplan/systemd-networkd are not supported")
	}
	if _, err := os.Stat("/etc/network/interfaces"); err != nil {
		return errors.New("missing /etc/network/interfaces; this tool requires ifupdown networking")
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
		cfg.RouteSrc = detectLocalFromDev(cfg.UnderlayFam, cfg.RouteDev)
	}

	local := cfg.RouteSrc
	if local == "" {
		local = "%any"
	}
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

	innerDefault := ""
	innerCIDR := innerDefault
	if err := askInput(prompter, "Inner local address/CIDR", &innerCIDR, validateCIDR(cfg.InnerFam)); err != nil {
		return err
	}
	cfg.InnerCIDR = innerCIDR

	authChoice := "1"
	if err := askSelectRaw(prompter, "Authentication method", []ui.Option{
		{Label: "1) PSK (pre-shared key)", Value: "1"},
		{Label: "2) RPK (raw public key)", Value: "2"},
	}, &authChoice); err != nil {
		return err
	}
	switch authChoice {
	case "1":
		cfg.AuthMethod = AuthPSK
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
	case "2":
		cfg.AuthMethod = AuthRPK
		if err := selectRPKAlgo(cfg, uiOut, prompter); err != nil {
			return err
		}
		if err := prepareRPK(cfg, uiOut, prompter); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid authentication choice: %s", authChoice)
	}

	algoChoice := "1"
	if err := askSelectRaw(prompter, "Algorithm profile", []ui.Option{
		{Label: "1) aes128gcm16-prfsha256 (recommended)", Value: "1"},
		{Label: "2) aes256gcm16-prfsha256", Value: "2"},
		{Label: "3) aes256gcm16-prfsha384 (high security)", Value: "3"},
	}, &algoChoice); err != nil {
		return err
	}

	ikeBase := ""
	switch algoChoice {
	case "1":
		ikeBase = "aes128gcm16-prfsha256"
		cfg.EspAlg = "aes128gcm16"
	case "2":
		ikeBase = "aes256gcm16-prfsha256"
		cfg.EspAlg = "aes256gcm16"
	case "3":
		ikeBase = "aes256gcm16-prfsha384"
		cfg.EspAlg = "aes256gcm16"
	default:
		return fmt.Errorf("invalid algorithm choice: %s", algoChoice)
	}

	if err := selectKexGroup(cfg, uiOut, prompter); err != nil {
		return err
	}
	cfg.IkeAlg = fmt.Sprintf("%s-%s", ikeBase, cfg.KexGroup)

	uiOut.Info("IKE lifetime: 1h, Child SA lifetime: 8h (adjust in config if needed)")

	encap, err := askConfirm(prompter, "Enable encap = yes?", false)
	if err != nil {
		return err
	}
	cfg.Encap = encap

	startAction := "trap"
	initiate, err := askConfirm(prompter, "Actively initiate IKE (start_action = start)?", false)
	if err != nil {
		return err
	}
	if initiate {
		startAction = "start"
	}
	cfg.StartAction = startAction

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
		value = normalizeAnyToken(value)
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

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func isAny(s string) bool {
	return strings.EqualFold(normalizeAnyToken(s), "%any")
}

func normalizeAny(s string) string {
	s = normalizeAnyToken(s)
	if strings.EqualFold(s, "%any") {
		return "%any"
	}
	return s
}

func normalizeAnyToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	s = strings.ReplaceAll(s, "\uFF05", "%")
	if strings.EqualFold(s, "any") {
		return "%any"
	}
	return s
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

func detectLocalFromDev(fam int, dev string) string {
	if strings.TrimSpace(dev) == "" {
		return ""
	}
	args := []string{"-4", "-o", "addr", "show", "dev", dev, "scope", "global"}
	needle := "inet"
	if fam == 6 {
		args = []string{"-6", "-o", "addr", "show", "dev", dev, "scope", "global"}
		needle = "inet6"
	}
	out, err := sys.Output("ip", args...)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == needle {
				addr := fields[i+1]
				ip := strings.SplitN(addr, "/", 2)[0]
				if fam == 6 && strings.HasPrefix(strings.ToLower(ip), "fe80:") {
					continue
				}
				return ip
			}
		}
	}
	return ""
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

func selectRPKAlgo(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	options := []ui.Option{
		{Label: "ECDSA P-384 (recommended)", Value: RPKAlgoP384},
		{Label: "ECDSA P-256", Value: RPKAlgoP256},
		{Label: "ECDSA P-521", Value: RPKAlgoP521},
	}

	if supportsEd25519(uiOut) {
		options = append([]ui.Option{{Label: "Ed25519", Value: RPKAlgoEd25519}}, options...)
	}

	choice := options[0].Value
	if err := askSelectRaw(prompter, "RPK key algorithm", options, &choice); err != nil {
		return err
	}
	cfg.RPKAlgo = choice
	return nil
}

func prepareRPK(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	cfg.RPKLocalKey = cfg.Name + "-local"
	cfg.RPKRemoteKey = cfg.Name + "-remote"
	cfg.RPKLocalPrivFile = filepath.Join(cfg.SwanctlDir, "ecdsa", cfg.RPKLocalKey+".key")
	cfg.RPKLocalPubFile = filepath.Join(cfg.SwanctlDir, "pubkey", cfg.RPKLocalKey+".pub")
	cfg.RPKRemotePubFile = filepath.Join(cfg.SwanctlDir, "pubkey", cfg.RPKRemoteKey+".pub")

	if err := os.MkdirAll(filepath.Join(cfg.SwanctlDir, "ecdsa"), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(cfg.SwanctlDir, "pubkey"), 0755); err != nil {
		return err
	}

	localPrivExists := fileExists(cfg.RPKLocalPrivFile)
	localPubExists := fileExists(cfg.RPKLocalPubFile)
	if localPrivExists && localPubExists {
		reuse, err := askConfirm(prompter, "Local RPK key files exist. Reuse them?", true)
		if err != nil {
			return err
		}
		if reuse {
			der, err := readPublicKeyDER(cfg.RPKLocalPubFile)
			if err != nil {
				return err
			}
			cfg.RPKLocalPubDER = der
			existingAlgo, err := publicKeyAlgoFromDER(der)
			if err != nil {
				return err
			}
			if cfg.RPKAlgo != "" && existingAlgo != cfg.RPKAlgo {
				uiOut.Warn(fmt.Sprintf("Existing local RPK key is %s but %s was selected.", existingAlgo, cfg.RPKAlgo))
				ok, err := askConfirm(prompter, "Regenerate local RPK key pair with selected algorithm?", true)
				if err != nil {
					return err
				}
				if ok {
					if err := generateAndWriteRPK(cfg); err != nil {
						return err
					}
				} else {
					cfg.RPKAlgo = existingAlgo
				}
			} else {
				cfg.RPKAlgo = existingAlgo
			}
		} else {
			if err := generateAndWriteRPK(cfg); err != nil {
				return err
			}
		}
	} else if localPrivExists || localPubExists {
		uiOut.Warn("Only one of the local RPK key files exists.")
		ok, err := askConfirm(prompter, "Regenerate local RPK key pair now?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled; local RPK key files are incomplete")
		}
		if err := generateAndWriteRPK(cfg); err != nil {
			return err
		}
	} else {
		if err := generateAndWriteRPK(cfg); err != nil {
			return err
		}
	}

	uiOut.HR()
	uiOut.Title("Local RPK public key (base64 DER)")
	fmt.Fprintln(uiOut.Out, base64.StdEncoding.EncodeToString(cfg.RPKLocalPubDER))
	uiOut.Dim("Copy this string to the remote side and paste it when prompted.")
	uiOut.Info("Local RPK public key file: " + cfg.RPKLocalPubFile)
	uiOut.HR()

	remoteInput := ""
	if err := askInput(prompter, "Remote public key (base64 DER or path to PEM/DER file)", &remoteInput, func(v string) error {
		der, err := parsePublicKeyInput(v)
		if err != nil {
			return err
		}
		cfg.RPKRemotePubDER = der
		return nil
	}); err != nil {
		return err
	}

	if fileExists(cfg.RPKRemotePubFile) {
		overwrite, err := askConfirm(prompter, "Remote RPK public key file exists. Overwrite?", false)
		if err != nil {
			return err
		}
		if !overwrite {
			return errors.New("cancelled; remote public key file exists")
		}
	}
	if err := writePublicKeyPEM(cfg.RPKRemotePubFile, cfg.RPKRemotePubDER); err != nil {
		return err
	}
	uiOut.Ok("wrote: " + cfg.RPKRemotePubFile)
	return nil
}

func generateAndWriteRPK(cfg *Config) error {
	switch cfg.RPKAlgo {
	case RPKAlgoEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		if err := os.WriteFile(cfg.RPKLocalPrivFile, privPEM, 0600); err != nil {
			return err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return err
		}
		cfg.RPKLocalPubDER = pubDER
		return writePublicKeyPEM(cfg.RPKLocalPubFile, pubDER)
	case RPKAlgoP256, RPKAlgoP384, RPKAlgoP521:
		curve := elliptic.P256()
		switch cfg.RPKAlgo {
		case RPKAlgoP384:
			curve = elliptic.P384()
		case RPKAlgoP521:
			curve = elliptic.P521()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		privDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
		if err := os.WriteFile(cfg.RPKLocalPrivFile, privPEM, 0600); err != nil {
			return err
		}

		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		cfg.RPKLocalPubDER = pubDER
		return writePublicKeyPEM(cfg.RPKLocalPubFile, pubDER)
	default:
		return fmt.Errorf("unsupported RPK algorithm: %s", cfg.RPKAlgo)
	}
}

func parsePublicKeyInput(input string) ([]byte, error) {
	val := strings.TrimSpace(input)
	if val == "" {
		return nil, errors.New("value is required")
	}
	if val[0] == '@' {
		val = strings.TrimSpace(val[1:])
	}
	if fileExists(val) {
		return readPublicKeyDER(val)
	}
	compact := strings.Join(strings.Fields(val), "")
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, errors.New("invalid base64 or file path")
	}
	if err := validatePublicKeyDER(der); err != nil {
		return nil, err
	}
	return der, nil
}

func readPublicKeyDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		if err := validatePublicKeyDER(block.Bytes); err != nil {
			return nil, err
		}
		return block.Bytes, nil
	}
	if err := validatePublicKeyDER(data); err != nil {
		return nil, err
	}
	return data, nil
}

func validatePublicKeyDER(der []byte) error {
	if len(der) == 0 {
		return errors.New("public key is empty")
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return errors.New("invalid public key data")
	}
	return nil
}

func publicKeyAlgoFromDER(der []byte) (string, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", errors.New("invalid public key data")
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return RPKAlgoP256, nil
		case "P-384":
			return RPKAlgoP384, nil
		case "P-521":
			return RPKAlgoP521, nil
		default:
			return "", errors.New("unsupported ECDSA curve")
		}
	case ed25519.PublicKey:
		return RPKAlgoEd25519, nil
	default:
		return "", errors.New("unsupported public key type")
	}
}

func writePublicKeyPEM(path string, der []byte) error {
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func supportsEd25519(uiOut *ui.UI) bool {
	if !sys.LookPath("pki") {
		uiOut.Warn("pki not found; Ed25519 support check skipped")
		return false
	}
	if _, err := sys.Output("pki", "--gen", "--type", "ed25519", "--outform", "der"); err != nil {
		return false
	}
	return true
}

func selectKexGroup(cfg *Config, uiOut *ui.UI, prompter *ui.Prompter) error {
	supported, err := detectKeyExchangeGroups()
	if err != nil {
		uiOut.Warn("could not detect key exchange groups; falling back to defaults")
		supported = []string{"CURVE_25519", "ECP_384", "MODP_3072"}
	}

	options := buildKexOptions(supported, uiOut)
	if len(options) == 0 {
		return errors.New("no usable key exchange groups detected")
	}

	choice := options[0].Value
	if err := askSelectRaw(prompter, "Key exchange (IKE DH group)", options, &choice); err != nil {
		return err
	}
	cfg.KexGroup = choice
	return nil
}

func detectKeyExchangeGroups() ([]string, error) {
	out, err := sys.Output("swanctl", "--list-algs")
	if err != nil {
		return nil, err
	}

	var groups []string
	inKE := false
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.Contains(trim, ":") {
			parts := strings.SplitN(trim, ":", 2)
			section := strings.TrimSpace(parts[0])
			rest := ""
			if len(parts) > 1 {
				rest = strings.TrimSpace(parts[1])
			}
			if isKeyExchangeSection(section) {
				inKE = true
				if rest != "" {
					parseKexTokens(rest, &groups)
				}
			} else if inKE && rest == "" {
				break
			}
			if rest == "" {
				continue
			}
		}
		if !inKE {
			continue
		}
		parseKexTokens(trim, &groups)
	}
	if len(groups) == 0 {
		return nil, errors.New("no key exchange groups found")
	}
	return groups, nil
}

func isKeyExchangeSection(section string) bool {
	section = strings.ToLower(strings.TrimSpace(section))
	switch section {
	case "key exchange", "key exchange methods", "ke":
		return true
	default:
		return false
	}
}

func parseKexTokens(line string, groups *[]string) {
	for _, tok := range strings.Fields(line) {
		name := strings.Trim(tok, ",")
		if idx := strings.Index(name, "["); idx >= 0 {
			name = name[:idx]
		}
		name = strings.TrimSpace(name)
		if name != "" {
			*groups = append(*groups, strings.ToUpper(name))
		}
	}
}

func buildKexOptions(supported []string, uiOut *ui.UI) []ui.Option {
	secureOrder := []string{
		"CURVE_25519",
		"CURVE_448",
		"ECP_384",
		"ECP_521",
		"MODP_4096",
		"MODP_3072",
	}
	supportedSet := make(map[string]bool, len(supported))
	for _, name := range supported {
		supportedSet[name] = true
	}

	options := make([]ui.Option, 0)
	for _, name := range secureOrder {
		if !supportedSet[name] {
			continue
		}
		proposal, ok := kexProposalName(name)
		if !ok {
			continue
		}
		label := name
		if len(options) == 0 {
			label = label + " (recommended)"
		}
		options = append(options, ui.Option{Label: label, Value: proposal})
	}

	if len(options) > 0 {
		return options
	}

	uiOut.Warn("no preferred secure key exchange groups found; showing all detected groups")
	for _, name := range supported {
		proposal, ok := kexProposalName(name)
		if !ok {
			continue
		}
		options = append(options, ui.Option{Label: name, Value: proposal})
	}
	return options
}

func kexProposalName(name string) (string, bool) {
	switch strings.ToUpper(name) {
	case "MODP_1024":
		return "modp1024", true
	case "MODP_1536":
		return "modp1536", true
	case "MODP_2048":
		return "modp2048", true
	case "MODP_3072":
		return "modp3072", true
	case "MODP_4096":
		return "modp4096", true
	case "MODP_6144":
		return "modp6144", true
	case "MODP_8192":
		return "modp8192", true
	case "MODP_1024_160":
		return "modp1024s160", true
	case "MODP_2048_224":
		return "modp2048s224", true
	case "MODP_2048_256":
		return "modp2048s256", true
	case "ECP_192":
		return "ecp192", true
	case "ECP_224":
		return "ecp224", true
	case "ECP_256":
		return "ecp256", true
	case "ECP_384":
		return "ecp384", true
	case "ECP_521":
		return "ecp521", true
	case "ECP_224_BP":
		return "ecp224bp", true
	case "ECP_256_BP":
		return "ecp256bp", true
	case "ECP_384_BP":
		return "ecp384bp", true
	case "ECP_512_BP":
		return "ecp512bp", true
	case "CURVE_25519":
		return "curve25519", true
	case "CURVE_448":
		return "curve448", true
	default:
		return "", false
	}
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
	b.WriteString("        unique = never\n")
	b.WriteString("        version = 2\n")
	fmt.Fprintf(&b, "        local_addrs = %s\n", cfg.LocalUnder)
	fmt.Fprintf(&b, "        remote_addrs = %s\n\n", cfg.RemoteUnder)
	if cfg.Encap {
		b.WriteString("        encap = yes\n")
	}
	b.WriteString("\n")
	b.WriteString("        local {\n")
	if cfg.AuthMethod == AuthRPK {
		b.WriteString("            auth = pubkey\n")
		fmt.Fprintf(&b, "            pubkeys = %s\n", filepath.Base(cfg.RPKLocalPubFile))
	} else {
		b.WriteString("            auth = psk\n")
	}
	fmt.Fprintf(&b, "            id = %s\n", cfg.LocalID)
	b.WriteString("        }\n")
	b.WriteString("        remote {\n")
	if cfg.AuthMethod == AuthRPK {
		b.WriteString("            auth = pubkey\n")
		fmt.Fprintf(&b, "            pubkeys = %s\n", filepath.Base(cfg.RPKRemotePubFile))
	} else {
		b.WriteString("            auth = psk\n")
	}
	fmt.Fprintf(&b, "            id = %s\n", cfg.RemoteID)
	b.WriteString("        }\n\n")
	b.WriteString("        children {\n")
	fmt.Fprintf(&b, "            %s-child {\n", cfg.Name)
	b.WriteString("                mode = tunnel\n")
	b.WriteString("                local_ts = 0.0.0.0/0,::/0\n")
	b.WriteString("                remote_ts = 0.0.0.0/0,::/0\n\n")
	fmt.Fprintf(&b, "                if_id_in = %d\n", cfg.IfID)
	fmt.Fprintf(&b, "                if_id_out = %d\n\n", cfg.IfID)
	startAction := cfg.StartAction
	if strings.TrimSpace(startAction) == "" {
		startAction = "trap"
	}
	fmt.Fprintf(&b, "                start_action = %s\n", startAction)
	b.WriteString("                close_action = trap\n\n")
	fmt.Fprintf(&b, "                esp_proposals = %s\n", cfg.EspAlg)
	b.WriteString("                rekey_time = 8h\n")
	b.WriteString("                life_time = 10h\n")
	b.WriteString("                dpd_action = clear\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n\n")
	fmt.Fprintf(&b, "        proposals = %s\n", cfg.IkeAlg)
	b.WriteString("        rekey_time = 1h\n")
	b.WriteString("        over_time = 90m\n")
	b.WriteString("        dpd_delay = 60s\n")
	b.WriteString("        dpd_timeout = 300s\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func buildSecrets(cfg *Config) string {
	var b strings.Builder
	if cfg.AuthMethod == AuthRPK {
		b.WriteString("# No PSK secrets required for RPK\n")
		return b.String()
	}
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

func printConfigSummary(cfg *Config, uiOut *ui.UI) {
	authLabel := "PSK"
	if cfg.AuthMethod == AuthRPK {
		authLabel = "RPK"
	}
	pskNote := "n/a"
	if cfg.AuthMethod == AuthPSK {
		pskNote = "not set"
		if strings.TrimSpace(cfg.PSK) != "" {
			pskNote = fmt.Sprintf("set (hidden, len=%d)", len(cfg.PSK))
		}
	}
	encap := "no"
	if cfg.Encap {
		encap = "yes"
	}

	uiOut.HR()
	uiOut.Title("Configuration summary")
	fmt.Fprintf(uiOut.Out, "Underlay IP version: IPv%d\n", cfg.UnderlayFam)
	fmt.Fprintf(uiOut.Out, "Primary device: %s\n", cfg.Device)
	fmt.Fprintf(uiOut.Out, "Remote underlay IP: %s\n", cfg.RemoteUnder)
	fmt.Fprintf(uiOut.Out, "Local underlay IP: %s\n", cfg.LocalUnder)
	fmt.Fprintf(uiOut.Out, "Local ID: %s\n", cfg.LocalID)
	fmt.Fprintf(uiOut.Out, "Remote ID: %s\n", cfg.RemoteID)
	fmt.Fprintf(uiOut.Out, "Tunnel name: %s\n", cfg.Name)
	fmt.Fprintf(uiOut.Out, "XFRM interface: %s\n", cfg.XfrmIf)
	fmt.Fprintf(uiOut.Out, "if_id: %d\n", cfg.IfID)
	fmt.Fprintf(uiOut.Out, "Inner IP version: IPv%d\n", cfg.InnerFam)
	fmt.Fprintf(uiOut.Out, "Inner CIDR: %s\n", cfg.InnerCIDR)
	fmt.Fprintf(uiOut.Out, "Auth method: %s\n", authLabel)
	if cfg.KexGroup != "" {
		fmt.Fprintf(uiOut.Out, "Key exchange group: %s\n", cfg.KexGroup)
	}
	fmt.Fprintf(uiOut.Out, "IKE proposal: %s\n", cfg.IkeAlg)
	fmt.Fprintf(uiOut.Out, "ESP proposal: %s\n", cfg.EspAlg)
	fmt.Fprintf(uiOut.Out, "Encap: %s\n", encap)
	startAction := cfg.StartAction
	if strings.TrimSpace(startAction) == "" {
		startAction = "trap"
	}
	fmt.Fprintf(uiOut.Out, "Start action: %s\n", startAction)
	fmt.Fprintf(uiOut.Out, "DPD: delay 60s timeout 300s action clear\n")
	if cfg.AuthMethod == AuthPSK {
		fmt.Fprintf(uiOut.Out, "PSK: %s\n", pskNote)
	} else {
		if cfg.RPKAlgo != "" {
			fmt.Fprintf(uiOut.Out, "RPK key algorithm: %s\n", cfg.RPKAlgo)
		}
		fmt.Fprintf(uiOut.Out, "Local private key: %s\n", cfg.RPKLocalPrivFile)
		fmt.Fprintf(uiOut.Out, "Local public key: %s\n", cfg.RPKLocalPubFile)
		fmt.Fprintf(uiOut.Out, "Remote public key: %s\n", cfg.RPKRemotePubFile)
	}
	if cfg.RouteDev != "" {
		fmt.Fprintf(uiOut.Out, "Route device: %s\n", cfg.RouteDev)
	}
	if cfg.RouteSrc != "" {
		fmt.Fprintf(uiOut.Out, "Route source: %s\n", cfg.RouteSrc)
	}
	fmt.Fprintf(uiOut.Out, "Conn file: %s\n", cfg.ConnFile)
	fmt.Fprintf(uiOut.Out, "Secrets file: %s\n", cfg.SecretsFile)
	fmt.Fprintf(uiOut.Out, "Iface file: %s\n", cfg.IfaceFile)
	uiOut.HR()
	if cfg.AuthMethod == AuthPSK {
		uiOut.Dim("PSK value is stored in the secrets file.")
	} else {
		uiOut.Dim("RPK public keys are stored in swanctl/pubkey.")
	}
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
	if cfg.AuthMethod == AuthPSK {
		fmt.Fprintf(uiOut.Out, "  - Same PSK (see %s)\n", cfg.SecretsFile)
	} else {
		fmt.Fprintf(uiOut.Out, "  - Your RPK public key (see %s)\n", cfg.RPKLocalPubFile)
		fmt.Fprintf(uiOut.Out, "  - You must have their RPK public key (see %s)\n", cfg.RPKRemotePubFile)
	}
	fmt.Fprintf(uiOut.Out, "  - Symmetric underlay IPs\n")
	fmt.Fprintf(uiOut.Out, "  - Same if_id: %d (recommended)\n", cfg.IfID)
	fmt.Fprintf(uiOut.Out, "  - Symmetric inner IPs (/127 or /31)\n")
	uiOut.HR()
	uiOut.Info("PFS note: DH group is encoded in the IKE proposal (modp/ecp)")
	uiOut.Info("Rekey performs a fresh DH exchange for PFS")
	uiOut.HR()
}
