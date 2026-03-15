# go-xfrm

## Quick Start

Run from GitHub (no clone, downloads latest release and runs):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sudogeeker/go-xfrm/main/run.sh)
```

By default it installs to `./bin` under your current working directory when run this way.

Run via `go run` from GitHub:

```bash
sudo go run github.com/sudogeeker/go-xfrm/cmd/xfrmgen@latest
```

Run locally after cloning:

```bash
./run.sh
```

A small interactive generator for XFRM interface + strongSwan (swanctl) configs.
It helps you build a site-to-site IPsec/IKEv2 tunnel with modern crypto defaults,
plus an option for PSK or RPK (raw public key) authentication.

This README is a tutorial: follow it top to bottom once, then reuse the quick steps.

---

## What It Generates

The tool writes three files:

- `swanctl` connection config: `/etc/swanctl/conf.d/<ifname>.conf`
- `swanctl` secrets config: `/etc/swanctl/conf.d/<ifname>.secrets` (PSK only)
- XFRM interface config: `/etc/network/interfaces.d/<ifname>.cfg`

It also ensures:

- `/etc/swanctl/swanctl.conf` includes `conf.d/*.conf` and `conf.d/*.secrets`
- `/etc/network/interfaces` sources `/etc/network/interfaces.d/*`

---

## Requirements

- Linux with XFRM support
- root access
- strongSwan + swanctl installed
- `ip` command available
- ifupdown networking (`/etc/network/interfaces`) is required
  netplan or systemd-networkd are not supported by this tool

Recommended packages on Debian/Ubuntu:

- `charon-systemd`
- `strongswan-swanctl`
- `strongswan-libcharon`
- `libstrongswan-standard-plugins`
- `libstrongswan-extra-plugins`
- `libcharon-extra-plugins`

---

## Build

```
make build
```

Binary is written to `./bin/xfrmgen`.

---

## Run

```
sudo ./bin/xfrmgen
```

The wizard will prompt you for:

1. Underlay IP version (v4/v6)
2. Primary device (e.g. `eth0`)
3. Remote underlay IP
4. Local underlay IP
5. Local ID / Remote ID
6. Tunnel name (`ipsec-<name>` interface will be created)
7. Inner IP version
8. Inner CIDR
9. Authentication method (PSK or RPK)
10. Crypto profile (AES-GCM + PRF)
11. Key exchange (IKE DH group) from detected safe options
12. NAT encapsulation option

After collection, the tool prints a full configuration summary.

---

## Authentication Options

### 1) PSK (Pre-Shared Key)

- Simple and quick.
- Best for small, fixed pairs.
- The tool can auto-generate a high-entropy PSK.

### 2) RPK (Raw Public Key)

- Similar to WireGuard-style static public keys.
- No certificates or expiry.
- You must exchange public keys between peers.

The tool will:

1. Generate a local keypair if needed.
2. Print a base64 DER public key for copy/paste.
3. Ask you to paste the peer's public key (base64 DER or a file path).
4. Write the peer pubkey into `/etc/swanctl/pubkey`.

---

## RPK: Copy/Paste Workflow (Two Sides)

On **both** sides, run the tool and select `RPK`.

1. Each side prints a `Local RPK public key (base64 DER)`.
2. Copy that string and paste into the other side when prompted.
3. Complete the remaining prompts.

Result: each side has its own private key and the peer's public key.

---

## Key Exchange (IKE DH Group)

The tool runs `swanctl --list-algs` and parses the **key exchange** section.
It then offers only **strong** groups if available:

- `CURVE_25519`
- `CURVE_448`
- `ECP_384`
- `ECP_521`
- `MODP_4096`
- `MODP_3072`

If detection fails, it falls back to a safe default list.

---

## RPK Key Algorithm Selection

When using RPK, you can choose:

- ECDSA P-384 (recommended)
- ECDSA P-256
- ECDSA P-521
- Ed25519 (only shown if supported by your local `pki` backend)

Ed25519 availability is checked by running:

```
pki --gen --type ed25519 --outform der
```

If that command fails, Ed25519 is hidden from the menu.

---

## Apply and Connect

Load configs, then bring up the interface and tunnel:

```
systemctl enable --now strongswan
swanctl --load-all
ifup ipsec-<name>
```

Verify:

```
swanctl --list-conns
swanctl --list-sas
ip link show ipsec-<name>
ip addr show ipsec-<name>
```

If you want to manually initiate:

```
swanctl --initiate --child <name>-child
```

---

## Security Notes

- PSK is fine for a single pair if the key is random and well protected.
- RPK avoids shared secrets and scales better for multi-peer setups.
- Always protect private keys and restrict file permissions.

---

## License

MIT
