package app

import (
	"errors"
	"flag"
	"os"

	"github.com/sudogeeker/tunnel-helper/internal/sys"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

func Run(args []string) error {
	fs := flag.NewFlagSet("tunnel-helper", flag.ContinueOnError)
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

	for {
		uiOut.Clear()
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
			{Label: "0) Exit", Value: "exit"},
		}

		uiOut.Title("tunnel-helper - VPN / Tunnel Generator")
		if err := askSelectRaw(prompter, "Main Menu (Select an action)", options, &tunnelType); err != nil {
			// 如果在主菜单直接取消，则退出
			if isAbortErr(err) {
				return nil
			}
			return wrapAbort(err)
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
