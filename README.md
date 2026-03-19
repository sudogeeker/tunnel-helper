# tunnel-helper

A small interactive generator for multiple types of VPNs and tunnels. 
It supports creating configurations for **IPsec/IKEv2 (XFRM via strongSwan)**, **WireGuard**, **AmneziaWG**, **VXLAN**, **GRE**, and **OpenVPN (DCO)**.

## Table of Contents

- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Build and Run](#build-and-run)
- [Configuration Details](#configuration-details)
  - [IPsec/IKEv2 (XFRM) & Static XFRM](#ipsecikev2-xfrm--static-xfrm)
  - [WireGuard & AmneziaWG](#wireguard--amneziawg)
  - [VXLAN & GRE](#vxlan--gre)
  - [OpenVPN (DCO)](#openvpn-dco)
- [License](#license)

---

## Quick Start

Run from GitHub (downloads latest release and runs):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sudogeeker/tunnel-helper/main/run.sh)
```

To install the binary to `/usr/bin/tunnel-helper`:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sudogeeker/tunnel-helper/main/run.sh) --install
```

Run via `go run` from GitHub:

```bash
sudo go run github.com/sudogeeker/tunnel-helper/cmd/tunnel-helper@latest
```

Run locally after cloning:

```bash
./run.sh
```

---

## Requirements

- Linux with root access
- `ip` command available
- **For XFRM, VXLAN, and GRE:** ifupdown networking (`/etc/network/interfaces`) is required. *(netplan or systemd-networkd are not supported by this tool)*
- **For XFRM:** strongSwan + swanctl installed. Recommended: `charon-systemd`, `strongswan-swanctl`, `libstrongswan-extra-plugins`.
- **For WireGuard:** `wireguard-tools` (the script can auto-install this via `apt` if missing).
- **For AmneziaWG:** The script can automatically download, compile, and install the kernel module and tools from source if they are missing.
- **For OpenVPN:** `openvpn`, `dkms`, and `openvpn-dco-dkms` (the script can auto-install these via `apt` if missing).

---

## Build and Run

### Build

```bash
make build
```

Binary is written to `./bin/tunnel-helper`.

### Run

```bash
sudo ./bin/tunnel-helper
```

The wizard will first prompt you to select the tunnel type:

1. XFRM (IPsec/IKEv2 via strongSwan)
2. Static XFRM (Manual Keying)
3. WireGuard
4. AmneziaWG
5. VXLAN
6. GRE
7. OpenVPN (DCO)

It will then guide you through an interactive process to collect IP addresses, keys, and other parameters, and generate the necessary configuration files.

---

## Configuration Details

### IPsec/IKEv2 (XFRM) & Static XFRM

#### IKEv2 (XFRM via strongSwan)
Generates three files:
- `swanctl` connection config: `/etc/swanctl/conf.d/<ifname>.conf`
- `swanctl` secrets config: `/etc/swanctl/conf.d/<ifname>.secrets` (PSK only)
- XFRM interface config: `/etc/network/interfaces.d/<ifname>.cfg`

Supports both **PSK (Pre-Shared Key)** and **RPK (Raw Public Key)** authentication. It automatically detects and offers strong DH groups for PFS.

#### Static XFRM (Manual Keying)
Generates a raw XFRM interface config in `/etc/network/interfaces.d/<ifname>.cfg`.
- **No IKE daemon (strongSwan) required.**
- **No UDP 500/4500 needed.**
- Uses manual SPI and encryption/authentication keys.
- Ideal for high-performance host-to-host tunnels where IKE negotiation is not desired.
- Supports AES-GCM (Recommended) and AES-CBC + HMAC-SHA256.

### WireGuard & AmneziaWG

Generates a standard WireGuard config in `/etc/wireguard/wg-<name>.conf` or AmneziaWG config in `/etc/amnezia/amneziawg/awg-<name>.conf`. 
- Can automatically generate key pairs.
- Supports specifying listening ports, MTU, PersistentKeepalive, and routing table.
- **AmneziaWG** adds obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4) and compiles kernel module/tools from source automatically if they're not installed.
- Use `wg-quick up wg-<name>` or `awg-quick up awg-<name>` to bring the interface up.

### VXLAN & GRE

Generates an ifupdown config in `/etc/network/interfaces.d/<name>.cfg`.
- For VXLAN: Uses `ip link add type vxlan` natively.
- For GRE: Uses `ip tunnel add mode gre/ip6gre`.
- Handles both IPv4 and IPv6 underlay/inner networks.
- Supports automatic replacement of inner IP addresses upon interface creation.

### OpenVPN (DCO)

Generates configuration files in `/etc/openvpn/server/` or `/etc/openvpn/client/`.
- Uses the `Listener (Server)` / `Initiator (Client)` model to define connections for P2P tunnels.
- Supports both **UDP** and **TCP**.
- Strongly encourages and enables **DCO (Data Channel Offload)** by default for maximum performance.
- Supports OpenVPN 2.6+ **Peer Fingerprint (RPK/TLS)**, auto-generating self-signed certificates and handling SHA256 fingerprints natively, removing the need for a complex CA infrastructure.
- Automatically handles kernel module loading (`ovpn-dco`).

---

## License

MIT
