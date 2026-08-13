# Policy-Based Routing (pbr)

[![OpenWrt](https://img.shields.io/badge/OpenWrt-Compatible-blueviolet)](https://openwrt.org)
[![Web UI](https://img.shields.io/badge/Web_UI-Available-blue)](https://docs.mossdef.org/pbr/)
[![License](https://img.shields.io/badge/License-GPL--3.0-lightgrey)](https://github.com/stangri/pbr/blob/master/LICENSE)

Flexible policy-based routing (PBR) framework for OpenWrt.  
Allows routing specific traffic (by IP, MAC, port, protocol, or domain) through a specific WAN, VPN, or tunnel.

## Features

- Route by IP, MAC, port, or domain name
- Works with WAN, VPNs (WireGuard, OpenVPN), or tunnels
- Lightweight shell-based implementation
- Optional Web UI integration via LuCI

**Full documentation:**  
[https://docs.mossdef.org/pbr/](https://docs.mossdef.org/pbr/)

**Reference notes:**  
[docs/tor.md](docs/tor.md) — how Tor routing works in `pbr`, and how to diagnose it when it doesn't.
