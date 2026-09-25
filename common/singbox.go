package common

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path"

	"github.com/charmbracelet/log"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	singJson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sethvargo/go-password/password"
)

// ReadSingBoxServerConfig reads and parses the sing-box server configuration
// from "sing-box-config.json" located in the specified data directory.
// It uses sing-box's internal JSON parsing capabilities.
func ReadSingBoxServerConfig(dataDir string) (*option.Options, error) {
	data, err := os.ReadFile(path.Join(dataDir, "sing-box-config.json"))
	if err != nil {
		return nil, err
	}
	globalCtx := libbox.BaseContext(nil)

	opt, err := singJson.UnmarshalExtendedContext[option.Options](globalCtx, data)
	if err != nil {
		return nil, err
	}
	return &opt, nil
}

// RevokeUser removes a named user from every user-based inbound. Inbounds that
// do not support named users are left unchanged.
func RevokeUser(dataDir, username string) error {
	cfg, err := ReadSingBoxServerConfig(dataDir)
	if err != nil {
		return err
	}
	changed := false
	for i := range cfg.Inbounds {
		switch in := cfg.Inbounds[i].Options.(type) {
		case *option.ShadowsocksInboundOptions:
			for j, u := range in.Users {
				if u.Name == username {
					in.Users = append(in.Users[:j], in.Users[j+1:]...)
					changed = true
					break
				}
			}
		case *option.VLESSInboundOptions:
			for j, u := range in.Users {
				if u.Name == username {
					in.Users = append(in.Users[:j], in.Users[j+1:]...)
					changed = true
					break
				}
			}
		case *option.VMessInboundOptions:
			for j, u := range in.Users {
				if u.Name == username {
					in.Users = append(in.Users[:j], in.Users[j+1:]...)
					changed = true
					break
				}
			}
		case *option.TrojanInboundOptions:
			for j, u := range in.Users {
				if u.Name == username {
					in.Users = append(in.Users[:j], in.Users[j+1:]...)
					changed = true
					break
				}
			}
		case *option.Hysteria2InboundOptions:
			for j, u := range in.Users {
				if u.Name == username {
					in.Users = append(in.Users[:j], in.Users[j+1:]...)
					changed = true
					break
				}
			}
		}
	}
	if !changed {
		return nil
	}
	if err = WriteSingBoxServerConfig(dataDir, cfg); err != nil {
		return err
	}
	return RestartSingBox(dataDir)
}

// firstUsableInbound returns the first inbound that can be represented as a
// client outbound. This avoids assuming that Shadowsocks is inbound zero.
func firstUsableInbound(cfg *option.Options) (*option.Inbound, error) {
	for i := range cfg.Inbounds {
		in := &cfg.Inbounds[i]
		switch in.Options.(type) {
		case *option.ShadowsocksInboundOptions, *option.VLESSInboundOptions,
			*option.VMessInboundOptions, *option.TrojanInboundOptions,
			*option.Hysteria2InboundOptions:
			return in, nil
		}
	}
	return nil, fmt.Errorf("no supported inbound found")
}

// GetShadowsocksInboundConfig is retained for initialization/firewall callers.
func GetShadowsocksInboundConfig(cfg *option.Options) (*option.ShadowsocksInboundOptions, error) {
	for i := range cfg.Inbounds {
		if in, ok := cfg.Inbounds[i].Options.(*option.ShadowsocksInboundOptions); ok {
			return in, nil
		}
	}
	return nil, fmt.Errorf("no shadowsocks inbound found")
}

// GenerateSingBoxConnectConfig copies the selected server inbound into a
// client outbound. Protocol-specific options (TLS, transport, Reality, etc.)
// are preserved, while the listen address is replaced with the public server
// address. Shadowsocks keeps its per-user password behavior.
func GenerateSingBoxConnectConfig(dataDir, publicIP, username string) ([]byte, error) {
	cfg, err := ReadSingBoxServerConfig(dataDir)
	if err != nil {
		return nil, err
	}
	in, err := firstUsableInbound(cfg)
	if err != nil {
		return nil, err
	}
	var outbound option.Outbound
	switch inOpts := in.Options.(type) {
	case *option.ShadowsocksInboundOptions:
		pw := inOpts.Password
		if username != "admin" {
			for _, u := range inOpts.Users {
				if u.Name == username {
					pw = u.Password
					break
				}
			}
			if pw == inOpts.Password {
				pw = makeShadowsocksPassword()
				inOpts.Users = append(inOpts.Users, option.ShadowsocksUser{Name: username, Password: pw})
				if err = WriteSingBoxServerConfig(dataDir, cfg); err != nil {
					return nil, err
				}
				if err = RestartSingBox(dataDir); err != nil {
					return nil, err
				}
			}
		}
		outbound = option.Outbound{Type: "shadowsocks", Tag: "server-outbound", Options: &option.ShadowsocksOutboundOptions{ServerOptions: option.ServerOptions{Server: publicIP, ServerPort: inOpts.ListenPort}, Method: inOpts.Method, Password: pw}}
	case *option.VLESSInboundOptions:
		if len(inOpts.Users) == 0 {
			return nil, fmt.Errorf("vless inbound has no users")
		}
		u := inOpts.Users[0]
		for _, candidate := range inOpts.Users {
			if candidate.Name == username {
				u = candidate
				break
			}
		}
		outbound = option.Outbound{Type: "vless", Tag: "server-outbound", Options: &option.VLESSOutboundOptions{ServerOptions: option.ServerOptions{Server: publicIP, ServerPort: inOpts.ListenPort}, UUID: u.UUID, Flow: u.Flow, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: inboundTLSOptions(inOpts.TLS)}, Transport: inOpts.Transport}}
	case *option.VMessInboundOptions:
		if len(inOpts.Users) == 0 {
			return nil, fmt.Errorf("vmess inbound has no users")
		}
		u := inOpts.Users[0]
		for _, candidate := range inOpts.Users {
			if candidate.Name == username {
				u = candidate
				break
			}
		}
		outbound = option.Outbound{Type: "vmess", Tag: "server-outbound", Options: &option.VMessOutboundOptions{ServerOptions: option.ServerOptions{Server: publicIP, ServerPort: inOpts.ListenPort}, UUID: u.UUID, AlterId: u.AlterId, Security: "auto", OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: inboundTLSOptions(inOpts.TLS)}, Transport: inOpts.Transport}}
	case *option.TrojanInboundOptions:
		if len(inOpts.Users) == 0 {
			return nil, fmt.Errorf("trojan inbound has no users")
		}
		u := inOpts.Users[0]
		for _, candidate := range inOpts.Users {
			if candidate.Name == username {
				u = candidate
				break
			}
		}
		outbound = option.Outbound{Type: "trojan", Tag: "server-outbound", Options: &option.TrojanOutboundOptions{ServerOptions: option.ServerOptions{Server: publicIP, ServerPort: inOpts.ListenPort}, Password: u.Password, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: inboundTLSOptions(inOpts.TLS)}, Transport: inOpts.Transport}}
	case *option.Hysteria2InboundOptions:
		if len(inOpts.Users) == 0 {
			return nil, fmt.Errorf("hysteria2 inbound has no users")
		}
		u := inOpts.Users[0]
		for _, candidate := range inOpts.Users {
			if candidate.Name == username {
				u = candidate
				break
			}
		}
		outbound = option.Outbound{Type: "hysteria2", Tag: "server-outbound", Options: &option.Hysteria2OutboundOptions{ServerOptions: option.ServerOptions{Server: publicIP, ServerPort: inOpts.ListenPort}, UpMbps: inOpts.UpMbps, DownMbps: inOpts.DownMbps, Obfs: inOpts.Obfs, Password: u.Password, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: inboundTLSOptions(inOpts.TLS)}}}
	default:
		return nil, fmt.Errorf("unsupported inbound type %q", in.Type)
	}
	opt := option.Options{Log: &option.LogOptions{Level: "debug", Output: "stdout"}, Inbounds: []option.Inbound{{Type: "socks5", Options: &option.SocksInboundOptions{ListenOptions: option.ListenOptions{ListenPort: 8888, Listen: common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1})))}}}}, Outbounds: []option.Outbound{outbound}}
	return badjson.MarshallObjects(opt)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func inboundTLSOptions(in *option.InboundTLSOptions) *option.OutboundTLSOptions {
	if in == nil {
		return nil
	}
	return &option.OutboundTLSOptions{Enabled: in.Enabled, ServerName: in.ServerName, Insecure: in.Insecure, ALPN: in.ALPN, MinVersion: in.MinVersion, MaxVersion: in.MaxVersion, Reality: func() *option.OutboundRealityOptions {
		if in.Reality == nil {
			return nil
		}
		return &option.OutboundRealityOptions{Enabled: true, ShortID: firstString(in.Reality.ShortID)}
	}()}
}

// WriteSingBoxServerConfig marshals the provided sing-box options into JSON
// and writes it to "sing-box-config.json" in the specified data directory.
func WriteSingBoxServerConfig(dataDir string, opt *option.Options) error {
	data, err := badjson.MarshallObjects(opt)
	if err != nil {
		return err
	}
	if err = os.WriteFile(path.Join(dataDir, "sing-box-config.json"), data, 0644); err != nil {
		return err
	}
	if !noSystemd {
		// in systemd mode, sing-box-extensions expects the config to be in /etc/sing-box-extensions/config.json
		// make sure that the path exists and copy the config
		if err = os.MkdirAll("/etc/sing-box-extensions", 0755); err != nil {
			return err
		}
		return os.WriteFile("/etc/sing-box-extensions/config.json", data, 0644)
	}
	// in non-systemd mode, we just write the config to the data directory
	return nil
}

// makeShadowsocksPassword generates a secure random password suitable for Shadowsocks
// (specifically for chacha20-ietf-poly1305, though the length is flexible).
// It returns the base64 encoded version of the generated password bytes.
func makeShadowsocksPassword() string {
	// generate a password. we are using chacha20-ietf-poly1305 so length can be anything
	passwordStr := password.MustGenerate(32, 10, 6, false, false)

	return base64.StdEncoding.EncodeToString([]byte(passwordStr))
}

// GenerateBasicSingBoxServerConfig creates a minimal initial sing-box server configuration.
// It sets up logging, a single Shadowsocks inbound listener (on a specified or random port)
// with a generated password, and writes the configuration to file.
func GenerateBasicSingBoxServerConfig(dataDir string, listenPort int) (*option.Options, error) {
	port := listenPort
	if port == 0 {
		// generate a number that is a valid non-privileged port
		port = rand.N(65535-1024) + 1024
	}
	pw := makeShadowsocksPassword()
	// generate basic shadowsocks config
	opt := option.Options{
		Log: &option.LogOptions{
			Level:  "debug",
			Output: "stdout",
		},
		Inbounds: []option.Inbound{
			{
				Type: "shadowsocks",
				Tag:  "ss-inbound",

				Options: &option.ShadowsocksInboundOptions{
					Method: "chacha20-ietf-poly1305",
					ListenOptions: option.ListenOptions{
						ListenPort: uint16(port),
						Listen:     common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{0, 0, 0, 0}))),
					},
					Password: pw,
				},
			},
		},
	}
	log.Infof("Writing intial vpn config to sing-box-config.json")
	return &opt, WriteSingBoxServerConfig(dataDir, &opt)
}

// CheckSingBoxInstalled checks if the 'sing-box' executable is available in the system's PATH.
func CheckSingBoxInstalled() bool {
	_, err := exec.LookPath(SingBoxExe)
	return err == nil
}

// ValidateSingBoxConfig uses the 'sing-box check' command to validate the syntax
// of the configuration file located at "sing-box-config.json" in the data directory.
func ValidateSingBoxConfig(dataDir string) error {
	singBoxPath, err := exec.LookPath(SingBoxExe)
	if err != nil {
		return fmt.Errorf("'%s' not found in PATH: %w", SingBoxExe, err)
	}
	// check for non-zero exit code
	if err = exec.Command(singBoxPath, "check", "--config", path.Join(dataDir, "sing-box-config.json")).Run(); err != nil {
		return fmt.Errorf("failed to validate sing-box config: %w", err)
	}
	return nil
}

// noSystemd controls whether systemd is used for service management.
// If the environment variable NO_SYSTEMD is set to any non-empty value,
// sing-box will be managed directly using pkill and running the command.
// Otherwise, it assumes systemd is available and uses `systemctl restart sing-box`.
var noSystemd = os.Getenv("NO_SYSTEMD") != ""

const SingBoxExe = "lantern-box"

// RestartSingBox restarts the sing-box service.
// It either uses `systemctl restart sing-box` or, if noSystemd is true,
// kills any existing sing-box process and starts a new one directly using the
// configuration file in the data directory.
func RestartSingBox(dataDir string) error {
	if noSystemd {
		singBoxPath, _ := exec.LookPath(SingBoxExe)
		// kill process
		_ = exec.Command("pkill", "-9", SingBoxExe).Run()
		// start process
		return exec.Command(singBoxPath, "run", "--config", path.Join(dataDir, "sing-box-config.json")).Start()
	}

	return exec.Command("systemctl", "restart", SingBoxExe).Run()
}
