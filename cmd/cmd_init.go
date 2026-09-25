package main

import (
	"github.com/charmbracelet/log"
	"github.com/sagernet/sing-box/option"

	"github.com/getlantern/lantern-server-manager/common"
)

// InitCmd defines the structure for the 'init' subcommand.
// It currently doesn't hold any command-specific arguments but serves as the handler target.
type InitCmd struct {
}

// InitializeConfigs generates the initial server and sing-box configurations.
// It uses the global 'args' variable to access the data directory and port settings.
// It returns the generated ServerConfig, sing-box Options, and any error encountered.
func InitializeConfigs() (*ServerConfig, *option.Options, error) {
	config, err := GenerateServerConfig(args.DataDir, args.APIPort)
	if err != nil {
		return nil, nil, err
	}
	singboxConfig, err := common.GenerateBasicSingBoxServerConfig(args.DataDir, args.VPNPort)
	if err != nil {
		return nil, nil, err
	}
	return config, singboxConfig, nil
}

// Run executes the 'init' subcommand logic.
// It calls InitializeConfigs to generate the necessary configuration files
// and then prints the root access token information using printRootToken.
func (c InitCmd) Run() error {
	if config, singboxConfig, err := InitializeConfigs(); err != nil {
		return err
	} else {
		printRootToken(config, singboxConfig)
	}

	return nil
}

// attemptToOpenPorts opens the API port and every configured inbound port.
// It opens the API port defined in the ServerConfig and the VPN port
// defined in every configured sing-box inbound.
// It skips execution if noFirewallD is true or if firewall-cmd is not found.
func attemptToOpenPorts(config *ServerConfig, singBoxConfig *option.Options) {
	common.OpenFirewallPort(config.Port)
	for _, inbound := range singBoxConfig.Inbounds {
		switch in := inbound.Options.(type) {
		case interface{ TakeListenOptions() option.ListenOptions }:
			common.OpenFirewallPort(int(in.TakeListenOptions().ListenPort))
		}
	}
}

// printRootToken logs information about the server setup, including required open ports,
// the Lantern VPN connection URL, and a QR code representation of the URL.
func printRootToken(config *ServerConfig, singBoxConfig *option.Options) {
	ports := []int{config.Port}
	for _, inbound := range singBoxConfig.Inbounds {
		if in, ok := inbound.Options.(interface{ TakeListenOptions() option.ListenOptions }); ok {
			ports = append(ports, int(in.TakeListenOptions().ListenPort))
		}
	}
	log.Infof("Make sure that the following ports are open: %v", ports)
	log.Infof("Paste this link into Lantern VPN app:\n%s", config.GetNewServerURL())
	log.Printf("Or scan this QR code in Lantern VPN app:\n%s", config.GetQR())
}
