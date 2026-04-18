package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

func Run(args []string) error {
	fs := flag.NewFlagSet("tunnel-helper", flag.ContinueOnError)
	confDir := fs.String("confdir", "/etc/swanctl/conf.d", "swanctl config directory")
	srv6Apply := fs.Bool("srv6-apply", false, "apply SRv6 tunnels and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	uiOut := ui.New(os.Stdout, os.Stderr, os.Stdin)

	if *srv6Apply {
		if !sys.IsRoot() {
			return errors.New("run as root (sudo -i)")
		}
		var config SRv6Config
		b, err := os.ReadFile(SRv6ConfigFile)
		if err != nil {
			return fmt.Errorf("failed to read SRv6 config: %w", err)
		}
		if err := json.Unmarshal(b, &config); err != nil {
			return fmt.Errorf("failed to parse SRv6 config: %w", err)
		}
		return applySRv6(uiOut, &config)
	}

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

	for {
		tunnelType := "manager"
		options := []ui.Option{
			{Label: "1) Manage existing tunnels", Value: "manager"},
			{Label: "2) WireGuard", Value: "3"},
			{Label: "3) AmneziaWG", Value: "4"},
			{Label: "4) OpenVPN", Value: "7"},
			{Label: "5) VXLAN", Value: "5"},
			{Label: "6) GRE", Value: "6"},
			{Label: "7) XFRM with IKEv2", Value: "1"},
			{Label: "8) XFRM with Static Keys", Value: "2"},
			{Label: "9) SRv6 Tunnel", Value: "9"},
			{Label: "0) Exit", Value: "exit"},
		}

		// 将全局应用名称作为菜单系统的原生 Title，让它自动随选择器刷新/销毁
		if err := askSelectRaw(prompter, "tunnel-helper - VPN / Tunnel Generator", options, &tunnelType); err != nil {
			// 如果在主菜单直接取消，则退出
			if isAbortErr(err) {
				return nil
			}
			return wrapAbort(err)
		}

		if tunnelType == "exit" {
			return nil
		}

		if tunnelType == "exit" {
			return nil
		}

		var err error
		switch tunnelType {
		case "manager":
			err = runManager(uiOut, prompter, *confDir)
		case "1":
			err = runXFRM(uiOut, prompter, *confDir)
		case "2":
			err = runStaticXFRM(uiOut, prompter)
		case "3":
			err = runWireguard(uiOut, prompter)
		case "4":
			err = runAmneziaWG(uiOut, prompter)
		case "5":
			err = runVXLAN(uiOut, prompter)
		case "6":
			err = runGRE(uiOut, prompter)
		case "7":
			err = runOpenVPN(uiOut, prompter)
		case "9":
			err = runSRv6(uiOut, prompter)
		}

		if err != nil {
			err = wrapAbort(err)
			if err == ErrAborted {
				// 用户在子菜单选择了取消或返回，继续循环回到主菜单
				continue
			}
			return err
		}
	}
}
