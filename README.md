# HVPN-LINUX

A command-line client for managing HitVPN connections for Linux with advanced connection capabilities.

## Features

- **Connect**: Establish VPN connections using configuration URLs
- **Version**: Display version and system information

## Installation

### Prerequisites

- Go 1.24.6 or later
- Root privileges for TUN device operations

### Build from Source

```bash
git clone https://github.com/hvpdev/hvpn-linux.git
cd hvpn-linux
go mod tidy
go build
```

## Usage

### Connect Command

Establish a WireGuard VPN connection using a configuration URL:

```bash
sudo ./hvpn-linux connect [url] [flags]
```

**Flags:**
- `-I, --interface string`: Interface name for the VPN connection (default: `wg0` for WireGuard, `wgo0` for obfuscated)
- `-S, --script string`: Script path to run before interface up/down (executed via bash)
- `-D, --dns`: Skip DNS resolution for the VPN interface
- `-b, --background`: Run the program in background mode
- `-v, --verbose`: Run the program in verbose mode

**Script Support:**

When using the `-S, --script` flag, the specified script is executed via `bash` with the following:
- **Arguments:**
  - `action=start` or `action=stop` - indicates the action being performed
  - Interface name (e.g., `wg0`)
- **Environment Variables:** The script receives all configuration parameters as environment variables prefixed with `HITVPN_`:
  - `HITVPN_PROTO` - Protocol number
  - `HITVPN_PRIVKEY` - Private key (base64 encoded)
  - `HITVPN_SERVERPUBKEY` - Server public key (base64 encoded)
  - `HITVPN_SERVERIP4` - Server IPv4 address
  - `HITVPN_SERVERPORT` - Server port
  - `HITVPN_LOCALIP` - Local IP address
  - `HITVPN_DNSIP4` - DNS servers (comma-separated, if available)
  - `HITVPN_MTU` - MTU value (if specified)
  - `HITVPN_KEEPALIVE` - Keepalive interval in seconds (if specified)
  - `HITVPN_SERVERIP6` - Server IPv6 address (if available)
  - `HITVPN_OBFCTLPADLEN`, `HITVPN_OBFTRPADLEN`, `HITVPN_OBFJUNKMIN`, `HITVPN_OBFJUNKVAR`, `HITVPN_OBFJUNKMINCNT`, `HITVPN_OBFJUNKVARCNT` - Obfuscation parameters (if available)
  - `HITVPN_HSDATA` - Handshake data (base64 encoded, if available)

**Examples:**
```bash
# Connect in foreground mode with verbose output
sudo ./hvpn-linux connect https://hitray.io/... -v

# Connect with custom interface name
sudo ./hvpn-linux connect https://hitray.io/... -I wg0

# Connect in background mode
sudo ./hvpn-linux connect https://hitray.io/... -b

# Connect with custom script for interface configuration
sudo ./hvpn-linux connect https://hitray.io/... -S /path/to/script.sh

# Connect and skip DNS configuration
sudo ./hvpn-linux connect https://hitray.io/... -D
```

### Version Command

Display version and system information:

```bash
./hvpn-linux version
```

## Configuration

### Environment Variables

- `WG_PROCESS_BACKGROUND`: Set to "1" to run in background mode (used internally for daemonization)
- `WG_TUN_FD`: TUN device file descriptor (used internally for daemonization)
- `WG_UAPI_FD`: UAPI file descriptor (used internally for daemonization)

## Security Notes

- Requires root privileges for TUN device operations
