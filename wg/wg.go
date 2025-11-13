package wg

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hvpdev/applink"
	"github.com/hvpdev/wgobfgo"
	"github.com/hvpdev/wgobfparams"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ENV_WG_TUN_FD  = "WG_TUN_FD"
	ENV_WG_UAPI_FD = "WG_UAPI_FD"
)

func New(
	proto uint8,
	wgd *applink.AppLink2WgData,
	ifName string,
	tdev tun.Device,
	log *device.Logger,
) (*device.Device, error) {
	bind := conn.NewDefaultBind()
	if proto == applink.AppLinkProto_Obf {
		log.Verbosef("Enable obfuscation")
		setObfParams(&wgd.AppLink2WgObfParams, log)
		obfKey := wgobfgo.ObfKeyFromWgKeyStr(
			base64.StdEncoding.EncodeToString(wgd.ServerPubKey[:]),
			false,
		)
		bind = wgobfgo.NewObfBind(obfKey, bind)
	}

	device := device.NewDevice(tdev, bind, log)
	if device == nil {
		return nil, fmt.Errorf("failed to create device")
	}

	return device, nil
}

func ParseConfigLink(url string) (*applink.AppLink2ConfigWrap, error) {
	wrap, err := applink.AppLink2DecodeWrapUrl(url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	if len(wrap.Configs) != 1 {
		return nil, fmt.Errorf("expected exactly one config in URL: %w", err)
	}

	cfg := wrap.Configs[0]
	if cfg.Proto != applink.AppLinkProto_Wg && cfg.Proto != applink.AppLinkProto_Obf {
		return nil, fmt.Errorf("unsupported protocol: %d", cfg.Proto)
	}

	return &cfg, nil
}

func OpenTunDevice(ifaceName string, proto uint8) (tun.Device, string, error) {
	ifname, err := getIfaceName(ifaceName, proto)
	if err != nil {
		return nil, "", fmt.Errorf("error getting interface name: %w", err)
	}

	tunFd := os.Getenv(ENV_WG_TUN_FD)
	if tunFd == "" {
		tdev, err := tun.CreateTUN(ifname, device.DefaultMTU)
		return tdev, ifname, err
	}

	fd, err := strconv.ParseUint(tunFd, 10, 32)
	if err != nil {
		return nil, "", fmt.Errorf("invalid tun fd %s: %w", ENV_WG_TUN_FD, err)
	}
	if err = unix.SetNonblock(int(fd), true); err != nil {
		return nil, "", fmt.Errorf("set nonblock error: %w", err)
	}
	tdev, err := tun.CreateTUNFromFile(
		os.NewFile(uintptr(fd), ""),
		device.DefaultMTU,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create TUN device: %w", err)
	}

	ifname, err = tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, "", fmt.Errorf("error getting TUN device name: %w", err)
	}
	return tdev, ifname, nil
}

func OpenUAPIFile(interfaceName string) (*os.File, error) {
	uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
	if uapiFdStr == "" {
		return ipc.UAPIOpen(interfaceName)
	}

	fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uapi fd %s: %w", ENV_WG_UAPI_FD, err)
	}
	return os.NewFile(uintptr(fd), ""), nil
}

func UAPIListen(
	ifName string,
	uapiFile *os.File,
	device *device.Device,
) (net.Listener, <-chan error, error) {
	uapi, err := ipc.UAPIListen(ifName, uapiFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on uapi socket: %w", err)
	}

	errCh := runUAPIAcceptLoop(uapi, device)
	return uapi, errCh, nil
}

func runUAPIAcceptLoop(uapi net.Listener, device *device.Device) <-chan error {
	errCh := make(chan error, 10)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errCh <- err
				close(errCh)
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	return errCh
}

func Configure(wgd *applink.AppLink2WgData, ifName string, dnsSkip bool) error {
	if err := configureDevice(wgd, ifName); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}
	if err := pinServerUplink(wgd.ServerIp4); err != nil {
		return fmt.Errorf("failed to pin server uplink: %w", err)
	}
	if err := setupLinkIPv4(ifName, wgd.LocalIp, wgd.Mtu); err != nil {
		return fmt.Errorf("failed to setup link IPv4: %w", err)
	}
	if err := addDefaultViaWG(ifName); err != nil {
		return fmt.Errorf("failed to add default via %s: %w", ifName, err)
	}
	if !dnsSkip {
		if err := configureDNS(ifName, wgd.DnsIp4); err != nil {
			return fmt.Errorf("failed to configure DNS: %w", err)
		}
	}
	return nil
}

func Clear(wgd *applink.AppLink2WgData, ifname string, dnsSkip bool) error {
	if err := unpinServerUplink(wgd.ServerIp4); err != nil {
		return fmt.Errorf("failed to unpin server uplink: %w", err)
	}
	if !dnsSkip {
		if err := removeDNS(ifname); err != nil {
			return fmt.Errorf("failed to remove DNS: %w", err)
		}
	}
	return nil
}

func WaitHandshake(ifName string, timeout time.Duration, log *device.Logger) error {
	const checkInterval = 100 * time.Millisecond

	deadline := time.Now().Add(timeout)
	log.Verbosef("Waiting for WireGuard handshake to complete...")

	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl instance: %w", err)
	}
	defer wg.Close()

	for time.Now().Before(deadline) {
		dev, err := wg.Device(ifName)
		if err != nil {
			return fmt.Errorf("failed to get device: %w", err)
		}

		// Check if any peer has completed handshake
		for _, peer := range dev.Peers {
			if !peer.LastHandshakeTime.IsZero() {
				log.Verbosef("Handshake completed with peer %s at %s",
					peer.PublicKey.String(), peer.LastHandshakeTime.Format(time.RFC3339))
				return nil
			}
		}
		time.Sleep(checkInterval)
	}

	return fmt.Errorf("handshake timeout after %v", timeout)
}

func setObfParams(obfp *wgobfparams.AppLink2WgObfParams, logger *device.Logger) {
	if obfp.ObfCtlPadLen != nil {
		wgobfgo.OBFCTL_PADLEN = int(*obfp.ObfCtlPadLen)
	}
	if obfp.ObfTrPadLen != nil {
		wgobfgo.OBFTR_PADLEN = int(*obfp.ObfTrPadLen)
	}
	if obfp.ObfJunkMin != nil {
		wgobfgo.OBF_JUNK_MIN_SIZE = int(*obfp.ObfJunkMin)
	}
	if obfp.ObfJunkVar != nil {
		wgobfgo.OBF_JUNK_VAR_SIZE = int(*obfp.ObfJunkVar)
	}
	if obfp.ObfJunkMinCnt != nil {
		wgobfgo.OBF_JUNK_MIN_CNT = int(*obfp.ObfJunkMinCnt)
	}
	if obfp.ObfJunkVarCnt != nil {
		wgobfgo.OBF_JUNK_VAR_CNT = int(*obfp.ObfJunkVarCnt)
	}
	wgobfgo.SetupHandshake(obfp.HsData, logger)
}

func ParseWgLink(data []byte) (*applink.AppLink2WgData, error) {
	var wgd applink.AppLink2WgData
	if err := cbor.Unmarshal(data, &wgd); nil != err {
		return nil, fmt.Errorf("error unmarshalling WireGuard config: %w", err)
	}
	return &wgd, nil
}

func configureDevice(wgd *applink.AppLink2WgData, ifName string) error {
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl instance: %w", err)
	}
	defer wg.Close()

	privKey, err := wgtypes.ParseKey(base64.StdEncoding.EncodeToString(wgd.PrivKey[:]))
	if err != nil {
		return fmt.Errorf("failed to parse wg private key: %w", err)
	}
	pubKey, err := wgtypes.ParseKey(base64.StdEncoding.EncodeToString(wgd.ServerPubKey[:]))
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %w", err)
	}

	serverPeer := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Endpoint: &net.UDPAddr{
			IP:   ip4FromUint32(wgd.ServerIp4),
			Port: int(wgd.ServerPort),
		},
		ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}},
	}
	if wgd.Keepalive != nil {
		keepalive := time.Duration(*wgd.Keepalive) * time.Second
		serverPeer.PersistentKeepaliveInterval = &keepalive
	}

	cfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{serverPeer},
	}

	if err := wg.ConfigureDevice(ifName, cfg); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	return nil
}

func setupLinkIPv4(ifName string, local uint32, mtu *uint16) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link by name: %w", err)
	}

	if mtu != nil && *mtu > 0 {
		if err := netlink.LinkSetMTU(link, int(*mtu)); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   ip4FromUint32(local),
		Mask: net.CIDRMask(32, 32),
	}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("failed to replace address: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	return nil
}

func pinServerUplink(server uint32) error {
	serverIP := ip4FromUint32(server)
	routes, err := netlink.RouteGet(serverIP)
	if err != nil || len(routes) == 0 {
		return fmt.Errorf("failed to get routes for server: %w", err)
	}
	r := routes[0]
	host := &netlink.Route{
		Dst: &net.IPNet{
			IP:   serverIP,
			Mask: net.CIDRMask(32, 32),
		},
		LinkIndex: r.LinkIndex,
		Gw:        r.Gw,
		Src:       r.Src,
		Table:     r.Table,
		Scope:     r.Scope,
		Priority:  50,
		Protocol:  unix.RTPROT_STATIC,
	}
	return netlink.RouteReplace(host)
}

func unpinServerUplink(server uint32) error {
	serverIP := ip4FromUint32(server)
	host := &netlink.Route{
		Dst: &net.IPNet{
			IP:   serverIP,
			Mask: net.CIDRMask(32, 32),
		},
		Priority: 50,
		Protocol: unix.RTPROT_STATIC,
	}

	if err := netlink.RouteDel(host); err != nil {
		return fmt.Errorf("failed to delete server uplink: %w", err)
	}
	return nil
}

func addDefaultViaWG(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link by name: %w", err)
	}
	def := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Priority: 200,
		Protocol: unix.RTPROT_STATIC,
	}
	return netlink.RouteReplace(def)
}

func configureDNS(ifName string, dnsServers []uint32) error {
	if len(dnsServers) == 0 {
		return nil
	}

	content := "# Generated by hvpn-linux\n"
	for _, dns := range dnsServers {
		content += fmt.Sprintf("nameserver %s\n", ip4FromUint32(dns).String())
	}

	fmt.Printf("content: %s\n", content)
	cmd := exec.Command("resolvconf", "-a", ifName)
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set DNS with resolvconf: %w", err)
	}

	return nil
}

func removeDNS(ifName string) error {
	cmd := exec.Command("resolvconf", "-d", ifName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove DNS with resolvconf: %w", err)
	}
	return nil
}

func getIfaceName(ifaceName string, proto uint8) (string, error) {
	switch proto {
	case applink.AppLinkProto_Wg:
		if ifaceName != "" {
			return ifaceName, nil
		}
		return "wg0", nil
	case applink.AppLinkProto_Obf:
		if ifaceName != "" {
			if !wgobfgo.IsObfIfname(ifaceName) {
				return "", fmt.Errorf("interface name must start with %s", wgobfgo.IFNAME_PREFIX_OBF)
			}
			return ifaceName, nil
		}
		return "wgo0", nil
	}

	return "", fmt.Errorf("unsupported protocol: %d", proto)
}

func ip4FromUint32(x uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, x)
	return ip
}
