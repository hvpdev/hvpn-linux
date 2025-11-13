module github.com/hvpdev/hvpn-linux

replace github.com/hvpdev/wgobfgo => ../wgobfgo

go 1.24.6

require (
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/hvpdev/applink v0.0.0-20250826155816-e4aab4dd331f
	github.com/hvpdev/wgobfgo v0.0.0-20250909162101-77c548ded244
	github.com/hvpdev/wgobfparams v0.0.0-20250909161508-66183f1289db
	github.com/spf13/cobra v1.10.1
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.32.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
