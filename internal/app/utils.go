package app

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

var ErrAborted = errors.New("aborted")

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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseTunnelInsideAddrEnv(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, errors.New("TUNNEL_INSIDE_ADDR is empty")
	}
	if strings.Contains(value, "/") {
		ip, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return "", 0, fmt.Errorf("invalid TUNNEL_INSIDE_ADDR CIDR: %s", value)
		}
		ones, _ := ipNet.Mask.Size()
		if ip.To4() != nil {
			return fmt.Sprintf("%s/%d", ip.To4().String(), ones), 4, nil
		}
		return fmt.Sprintf("%s/%d", ip.String(), ones), 6, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", 0, fmt.Errorf("invalid TUNNEL_INSIDE_ADDR IP: %s", value)
	}
	if ip.To4() != nil {
		return ip.To4().String() + "/32", 4, nil
	}
	return ip.String() + "/128", 6, nil
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
