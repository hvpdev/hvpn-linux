package connect

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hvpdev/hvpn-linux/wg"

	"github.com/hvpdev/hvpn-linux/utils"

	"github.com/hvpdev/applink"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const ENV_WG_PROCESS_BACKGROUND = "WG_PROCESS_BACKGROUND"

var ConnectCmd = &cobra.Command{
	Use:   "connect [url]",
	Short: "Connect to HitVPN-Linux VPN using a connection URL",
	Args:  cobra.ExactArgs(1),
	Run:   runConnect,
}

var (
	ifaceName  string
	scriptPath string
	dnsSkip    bool
	background bool
	verbose    bool
)

const (
	SCRIPT_ACTION_START = "start"
	SCRIPT_ACTION_STOP  = "stop"
)

func init() {
	ConnectCmd.Flags().StringVarP(&ifaceName, "interface", "I", "", "Interface name for the VPN connection")
	ConnectCmd.Flags().StringVarP(&scriptPath, "script", "S", "", "Script path to run before interface up/down")
	ConnectCmd.Flags().BoolVarP(&dnsSkip, "dns", "D", false, "Skip DNS resolution for the VPN interface")
	ConnectCmd.Flags().BoolVarP(&background, "background", "b", false, "Run the program in background mode")
	ConnectCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Run the program in verbose mode")
}

func runConnect(cmd *cobra.Command, args []string) {
	cfg, err := wg.ParseConfigLink(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL: %s\n", err)
		os.Exit(1)
	}

	if err := runWg(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error running WireGuard: %s\n", err)
		os.Exit(1)
	}
}

func runWg(cfg *applink.AppLink2ConfigWrap) error {
	tdev, ifname, err := wg.OpenTunDevice(ifaceName, cfg.Proto)
	if err != nil {
		return fmt.Errorf("error opening TUN device: %w", err)
	}
	defer tdev.Close()

	uapi, err := wg.OpenUAPIFile(ifname)
	if err != nil {
		return fmt.Errorf("error opening UAPI file: %w", err)
	}
	defer uapi.Close()

	if getBackgroundMode() {
		return runBackground(tdev, uapi)
	}
	return runForeground(cfg, ifname, tdev, uapi)
}

func runForeground(
	cfg *applink.AppLink2ConfigWrap,
	ifName string,
	tdev tun.Device,
	uapiFile *os.File,
) error {
	log := utils.GetLogger(ifName, verbose)
	log.Verbosef("Starting wireguard-go")

	wgd, err := wg.ParseWgLink(cfg.CfgData)
	if err != nil {
		return fmt.Errorf("failed to parse WireGuard config: %w", err)
	}

	device, err := wg.New(cfg.Proto, wgd, ifName, tdev, log)
	if err != nil {
		return fmt.Errorf("failed to create device: %w", err)
	}
	defer device.Close()

	log.Verbosef("Device started")

	uapi, errCh, err := wg.UAPIListen(ifName, uapiFile, device)
	if err != nil {
		return fmt.Errorf("failed to listen on uapi socket: %w", err)
	}
	defer uapi.Close()
	log.Verbosef("UAPI listener started")

	if scriptPath == "" {
		if err := wg.Configure(wgd, ifName, dnsSkip); err != nil {
			return fmt.Errorf("failed to configure device: %w", err)
		}
		defer func() {
			if err := wg.Clear(wgd, ifName, dnsSkip); err != nil {
				log.Verbosef("failed to clear settings: %s", err)
			}
		}()
	} else {
		err := runScript(scriptPath, SCRIPT_ACTION_START, ifName, cfg.Proto, wgd)
		if err != nil {
			return fmt.Errorf("failed to run 'start' script: %w", err)
		}
		defer func() {
			err := runScript(scriptPath, SCRIPT_ACTION_STOP, ifName, cfg.Proto, wgd)
			if err != nil {
				log.Verbosef("failed to run 'stop' script: %s", err)
			}
		}()
	}

	shutdownCh := make(chan os.Signal, 10)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Verbosef("UAPI listener error: %s", err)
	case <-shutdownCh:
	case <-device.Wait():
	}

	log.Verbosef("Shutting down...")
	return nil
}

func runBackground(tdev tun.Device, uapiFile *os.File) error {
	path, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable: %w", err)
	}
	process, err := os.StartProcess(path, os.Args, buildAttrs(tdev, uapiFile))
	if err != nil {
		return fmt.Errorf("failed to start daemonized process: %w", err)
	}
	process.Release()
	return nil
}

func buildAttrs(tdev tun.Device, uapiFile *os.File) *os.ProcAttr {
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=3", wg.ENV_WG_TUN_FD))
	env = append(env, fmt.Sprintf("%s=4", wg.ENV_WG_UAPI_FD))
	env = append(env, fmt.Sprintf("%s=0", ENV_WG_PROCESS_BACKGROUND))

	var files [5]*os.File
	files[0], _ = os.Open(os.DevNull)
	files[3] = tdev.File()
	files[4] = uapiFile

	if utils.GetLogLevel(verbose) == device.LogLevelSilent {
		files[1], _ = os.Open(os.DevNull)
		files[2], _ = os.Open(os.DevNull)
	} else {
		files[1] = os.Stdout
		files[2] = os.Stderr
	}

	return &os.ProcAttr{Files: files[:], Dir: ".", Env: env}
}

func getBackgroundMode() bool {
	if background {
		return true
	}
	if os.Getenv(ENV_WG_PROCESS_BACKGROUND) == "1" {
		return true
	}
	return false
}

func runScript(
	scriptPath string,
	action string,
	ifName string,
	proto uint8,
	wgd *applink.AppLink2WgData,
) error {
	cmd := exec.Command("bash", scriptPath, fmt.Sprintf("action=%s", action), ifName)

	env := os.Environ()
	env = append(env, buildConfigEnvVars(proto, wgd)...)
	cmd.Env = env

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func buildConfigEnvVars(proto uint8, wgd *applink.AppLink2WgData) []string {
	var envVars []string

	envVars = append(envVars, fmt.Sprintf("HITVPN_PROTO=%d", proto))
	envVars = append(envVars, fmt.Sprintf(
		"HITVPN_PRIVKEY=%s", base64.StdEncoding.EncodeToString(wgd.PrivKey[:])))
	envVars = append(envVars, fmt.Sprintf(
		"HITVPN_SERVERPUBKEY=%s", base64.StdEncoding.EncodeToString(wgd.ServerPubKey[:])))
	envVars = append(envVars, fmt.Sprintf("HITVPN_SERVERIP4=%s", ip4ToString(wgd.ServerIp4)))
	envVars = append(envVars, fmt.Sprintf("HITVPN_SERVERPORT=%d", wgd.ServerPort))
	envVars = append(envVars, fmt.Sprintf("HITVPN_LOCALIP=%s", ip4ToString(wgd.LocalIp)))

	if len(wgd.DnsIp4) > 0 {
		dnsStrs := make([]string, len(wgd.DnsIp4))
		for i, dns := range wgd.DnsIp4 {
			dnsStrs[i] = ip4ToString(dns)
		}
		envVars = append(envVars, fmt.Sprintf("HITVPN_DNSIP4=%s", strings.Join(dnsStrs, ",")))
	}
	if wgd.Mtu != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_MTU=%d", *wgd.Mtu))
	}
	if wgd.Keepalive != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_KEEPALIVE=%d", *wgd.Keepalive))
	}
	if len(wgd.ServerIp6) > 0 {
		envVars = append(envVars, fmt.Sprintf("HITVPN_SERVERIP6=%s", ip6ToString(wgd.ServerIp6)))
	}

	if wgd.ObfCtlPadLen != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFCTLPADLEN=%d", *wgd.ObfCtlPadLen))
	}
	if wgd.ObfTrPadLen != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFTRPADLEN=%d", *wgd.ObfTrPadLen))
	}
	if wgd.ObfJunkMin != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFJUNKMIN=%d", *wgd.ObfJunkMin))
	}
	if wgd.ObfJunkVar != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFJUNKVAR=%d", *wgd.ObfJunkVar))
	}
	if wgd.ObfJunkMinCnt != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFJUNKMINCNT=%d", *wgd.ObfJunkMinCnt))
	}
	if wgd.ObfJunkVarCnt != nil {
		envVars = append(envVars, fmt.Sprintf("HITVPN_OBFJUNKVARCNT=%d", *wgd.ObfJunkVarCnt))
	}
	if len(wgd.HsData) > 0 {
		envVars = append(envVars, fmt.Sprintf("HITVPN_HSDATA=%s", base64.StdEncoding.EncodeToString(wgd.HsData)))
	}

	return envVars
}

func ip4ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

func ip6ToString(ip []byte) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7])
}
