# How Tor routing works in pbr

*Describes pbr 1.2.3 (ucode). The Tor path is unchanged from 1.1.6 onward —
same five rules, same chain, same gating — so a Tor problem is almost never a
pbr version problem. Behaviour verified against the mock test suite.*

> **Provenance, and a health warning.** This was written by Claude (Anthropic)
> on 2026-08-12/13, working through a pbr support-thread investigation: reading
> the pbr source and its git history, the dnsmasq and Tor manuals, and running
> tests against a live OpenWrt router. Most of it is verified against those
> sources or reproduced experimentally, but some is inference — and during that
> investigation several confident-sounding conclusions turned out to be wrong
> before the real cause surfaced (dnsmasq rebind protection, `all-servers`, and
> "`.onion` cannot be forwarded" were each proposed and then disproved).
>
> So treat this as a well-researched starting point rather than an authority.
> dnsmasq and OpenWrt behaviour changes between releases, and the file paths and
> defaults quoted here are from one system at one point in time. Check the
> commands against your own before relying on them.

Tor is the one "interface" in pbr that isn't an interface at all. Nothing is
routed to it — traffic is NAT-redirected into a local daemon. Understanding
that distinction explains almost every way a Tor setup fails.

Every other pbr target (`wan`, a WireGuard tunnel, an mwan4 strategy) gets a
routing table, a firewall mark and an `ip rule`. Packets are *marked* and then
*routed* out of a device.

Tor gets none of that. It has no device, no gateway, no table, no mark. Tor runs
on the router itself and listens on two local ports, so pbr's entire job is to
bend selected traffic into those ports using destination NAT. That is the whole
mechanism.

|                     | A normal interface                          | Tor                          |
| ------------------- | ------------------------------------------- | ---------------------------- |
| **Mechanism**       | mark + `ip rule` + routing table            | `redirect` (destination NAT) |
| **nft chain**       | `pbr_prerouting` / `_output` / `_forward`   | `pbr_dstnat`                 |
| **Firewall mark**   | allocated per interface                     | none — field is empty        |
| **Routing table**   | allocated per interface                     | none                         |
| **Covers**          | all ports, all protocols                    | only ports 53, 80 and 443    |
| **If it's down**    | kill-switch / leak per policy               | connection refused on those 3 ports |

---

## The path a request takes

Two separate things have to happen for an onion address to load, and they use
different ports and different destinations. DNS is what makes `.onion` special:
the name has no public record, so it can only be resolved by Tor itself.

```
                    answers with a virtual address from
              ┌──── the VirtualAddrNetwork range ◄─────────────┐
              │                                               │
              ▼                                               │
    ┌──────────────┐        ┌─────────────┐          ┌────────────────┐
    │  LAN client  │───────►│ pbr_dstnat  │──────────►│  Tor DNSPort   │───┐
    │ 192.168.1.50 │        │             │  udp :53  │ 127.0.0.1:9053 │   │
    └──────────────┘        │ jumped from │   → :9053 └────────────────┘   │
                            │  fw4 dstnat │                                ▼
                            │             │          ┌────────────────┐  ┌──────────────┐
                            │  5 redirect │──────────►│ Tor TransPort  │──►│ Tor network  │
                            │    rules    │ tcp :80   │ 127.0.0.1:9040 │  │ → .onion svc │
                            └─────────────┘  :443     └────────────────┘  └──────────────┘
                                             → :9040
```

The client never learns the onion service's real address. Tor invents a private
address for the name (`AutomapHostsOnResolve`) from whatever range
`VirtualAddrNetworkIPv4` specifies, hands it back as the DNS answer, and then
recognises that address again when the connection arrives at its TransPort.

Do not assume the range. Tor's own default is `127.192.0.0/10` (and
`[FE80::]/10` for IPv6), while OpenWrt's Tor client guide sets
`172.16.0.0/12`, and much third-party material uses `10.192.0.0/10`. Read the
actual value out of the running config before deciding a set looks empty —
checking for the wrong prefix is an easy way to misdiagnose this.

---

## What pbr does, in order

### 1. Detect that Tor is running

Three conditions, all required: `tor` is not in `ignored_interface`,
`/etc/tor/torrc` exists and is non-empty, and `ubus call service list` reports a
`tor` instance with `running: true`. If any fails, Tor is skipped entirely and
no rules are written.

> `network.uc` — `is_tor_running()`

### 2. Read the two ports out of torrc

pbr greps `DNSPort` and `TransPort` from `/etc/tor/torrc`, falling back to
`9053` and `9040`. These become the redirect targets.

Two limits worth knowing, because both fail silently: pbr reads **only that one
file** — it does not follow `%include` directives or read `/etc/tor/conf.d`, so
ports defined in an included file are never seen. And it recognises only the
`address:port` form. Either way it falls back to 9053/9040, which is invisible
if those happen to be the ports in use, and a dead redirect if they are not.

This matters more than it looks: OpenWrt's own Tor client guide writes its
config to **`/etc/tor/custom`** and wires it in with
`tor.conf.tail_include`, not to `torrc`. Anyone following the official guide
therefore has ports pbr cannot see. It works today only because the guide
happens to use 9053/9040 — the same values as pbr's fallback.

> `pbr.uc` — `_get_tor_dns_port()` / `_get_tor_traffic_port()`

### 3. Register a synthetic interface

A registry entry named `tor` is created with empty device, mark, table and
priority. This is what makes `tor` appear in the status output — the "gateway"
column shows the port mapping `53->9053` and `80,443->9040` rather than an
address, because there is no gateway to show.

> `pbr.uc` — `interface_process.tor('create')`, runs before policies

### 4. Turn each Tor policy into five redirect rules

Any policy whose interface is `tor` is forced onto the `dstnat` chain, and its
`dest_port` and `proto` are cleared — Tor decides those, not the policy. Five
rules are emitted per policy, always the same five.

> `pbr.uc` — `policy_routing()`, tor branch

### 5. Hook the chain into fw4

`pbr_dstnat` is created and inserted at the top of fw4's own `dstnat` chain. pbr
also health-checks that fw4's `dstnat` chain exists whenever Tor is running, and
errors out if it doesn't.

> `nft.uc` — `insert rule inet fw4 dstnat jump pbr_dstnat`

### The five rules

```
udp dport 53  redirect to :9053   # Tor-DNS-UDP
tcp dport 80  redirect to :9040   # Tor-HTTP-TCP
udp dport 80  redirect to :9040   # Tor-HTTP-UDP
tcp dport 443 redirect to :9040   # Tor-HTTPS-TCP
udp dport 443 redirect to :9040   # Tor-HTTPS-UDP
```

> **Consequence worth knowing.** That list is exhaustive and hard-coded.
> Anything on another port — an onion service on `:8080`, SSH, XMPP, a mail
> client — is **never** redirected and leaves through the normal uplink. A Tor
> policy is not a kill switch; it is a redirect for three ports.

Note the two UDP rules for 80 and 443 do not do what they appear to. Tor's
`TransPort` accepts **TCP only**, so nothing is listening for the UDP that gets
redirected to it. The practical effect is to blackhole UDP on those ports rather
than carry it — which does stop QUIC/HTTP3 on 443 slipping past Tor, but by
refusing it rather than routing it. Only the TCP rules move traffic through Tor.

The same asymmetry applies at the other end: Tor's `DNSPort` is UDP-only, which
is why there is no `tcp dport 53` rule to match the UDP one. Adding one would
redirect TCP DNS to a port that cannot answer it.

---

## How traffic gets selected — and what each mode depends on

Those five rules are prefixed with whatever the policy matches on. That prefix
decides whether a setup works, and there are two very different modes.

### Mode A — match on source (`src_addr`, no `dest_addr`)

```
  client ───► ip saddr { 192.168.1.50 }          ───► Tor TransPort
              tcp dport 443 redirect to :9040         matches on packet 1
              — no destination condition —
```

Matches on the first packet and needs nothing else.

### Mode B — match on domain (`dest_addr = onion`)

```
  client ───► ip daddr @pbr_tor_4_dst_ip_<uid>     ───► Tor TransPort
              tcp dport 443 redirect to :9040           only once the set
              — gated on the set —                      contains the address
                        ▲
                        │ must be filled first
                  ┌───────────┐        ┌────────────┐        ┌──────────┐
                  │  nftset   │◄───────│  dnsmasq   │◄───────│   Tor    │
                  │           │  adds  │ /onion/ →  │ answer │ DNSPort  │
                  └───────────┘ answer │ 127.0.0.1  │        └──────────┘
                                       └────────────┘
```

Listing a domain such as `onion` in `dest_addr` triggers mode B. pbr creates a
set named `pbr_tor_4_dst_ip_<uid>`, writes a line into its dnsmasq include file,
and prefixes all five rules with `ip daddr @<set>`:

```
nftset=/onion/4#inet#fw4#pbr_tor_4_dst_ip_<uid> # <policy name>
```

**`<uid>` is the UCI section id, not the policy name** — typically something like
`cfg0c6ff5`. Use the name from `nft list chain inet fw4 pbr_dstnat`, not the
label you gave the policy, when inspecting the set.

**Mode B requires `resolver_set = dnsmasq.nftset`.** That setting is what makes
pbr hand the domain to dnsmasq to resolve, rather than resolving it itself.
Three conditions must all hold, and none of them is announced:

- `pbr.config.resolver_set` is `dnsmasq.nftset`. Unset, `none`, or
  `unbound.nftset` all fall back to resolving the name directly — which for
  `.onion` can never succeed, and surfaces as `ERROR: Failed to resolve 'onion'`.
- dnsmasq is built with nftset support. pbr detects this by grepping
  `dnsmasq --version` for `nftset` in the compile options; without it the
  fallback applies just the same.
- The domain is a **destination**. The set path is skipped for `src_addr`
  entirely, so a domain there is always resolved directly — meaning an onion
  name in `src_addr` cannot work under any configuration.

Note that *all five* rules carry the `ip daddr @<set>` prefix, including the DNS
one. A client's query is addressed to the router, which is never in the set, so
in mode B the DNS redirect never fires and name resolution always goes through
dnsmasq. That is what makes mode B able to work at all — but it also makes it
fragile in ways mode A is not:

- Nothing matches until dnsmasq has resolved a `*.onion` name **and** written
  the answer into the set. (dnsmasq writes it while processing the reply, before
  the client receives it, so this is not a race in practice — but it does mean
  the set is empty until the first lookup happens.)
- **On OpenWrt, dnsmasq will not forward `.onion` — and adding a server line for
  it does not help.** RFC 7686 reserves `.onion` as a special-use name, but
  dnsmasq itself does not act on that: a bare instance forwards `.onion`
  happily. OpenWrt is what blocks it, by shipping
  `/usr/share/dnsmasq/rfc6761.conf` (named for RFC 6761, which covers `test`,
  `localhost` and `invalid`; `.onion` was added later by RFC 7686 and lives in
  the same file):

  ```
  server=/bind/
  server=/invalid/
  server=/local/
  server=/localhost/
  server=/onion/      ← addressless: "answer locally, never forward"
  server=/test/
  ```

  and including it from the init script — gated, oddly, on the `boguspriv`
  option rather than anything to do with RFC6761:

  ```
  RFC6761FILE="/usr/share/dnsmasq/rfc6761.conf"
  config_get_bool boguspriv "$cfg" boguspriv 1
  [ "$boguspriv" -gt 0 ] && {
          xappend "--bogus-priv"
          [ -r "$RFC6761FILE" ] && xappend "--conf-file=$RFC6761FILE"
  }
  ```

  With that file loaded, a correct `server=/onion/127.0.0.1#9053` **registers
  and is then overridden.** Both appear in the startup log, and the local
  declaration wins:

  ```
  using nameserver 127.0.0.1#9053 for domain onion   ← your server line, registered
  using only locally-known addresses for onion       ← rfc6761.conf — and this wins
  ```

  Order does not help: dnsmasq normalises the server list, and the local
  declaration wins wherever it appears (both orderings verified on dnsmasq
  2.93). The file also sits outside the usual places (`/var/etc`,
  `/tmp/dnsmasq.d`, `serversfile`), which is why it is easy to miss — and this
  is how a setup that worked on an older OpenWrt breaks with no configuration
  change of your own.

  Three ways out, none of them free:

  | Fix | Survives upgrade | Cost |
  | --- | --- | --- |
  | Source-matched policy (drop `dest_addr`) | ✓ no dnsmasq involvement at all | that client's DNS all goes via Tor, so local filtering stops applying to it |
  | `uci set dhcp.@dnsmasq[0].boguspriv='0'` | ✓ supported UCI | blunt: the same flag gates `--bogus-priv`, so you also lose that and un-localise all six RFC6761 domains |
  | Comment `server=/onion/` in `rfc6761.conf` | ✗ package file | surgical, but silently reverts on upgrade |

  > **`boguspriv='0'` works by accident, so do not rely on it.** It is not a
  > control for RFC6761 — it happens to gate the `--conf-file` include as well
  > as `--bogus-priv`, which looks like a packaging slip rather than a decision.
  > If OpenWrt ever decouples the two (the correct fix), `boguspriv='0'` will
  > keep disabling `bogus-priv` while no longer removing `server=/onion/`, and
  > `.onion` will quietly stop resolving again with no configuration change of
  > your own — the same way this broke in the first place.
  >
  > **Re-check after every OpenWrt upgrade.** Instantly, from the generated
  > config, with no restart:
  >
  > ```sh
  > grep -c rfc6761 /var/etc/dnsmasq.conf.*   # 0 = .onion forwardable, 1 = localised
  > ```
  >
  > or behaviourally, reading one clean startup block:
  >
  > ```sh
  > /etc/init.d/dnsmasq restart; sleep 2
  > logread | grep "locally-known addresses for onion" \
  >   && echo "STILL LOCALISED — .onion will not forward" \
  >   || echo "OK — .onion can be forwarded to Tor"
  > ```
  >
  > The source-matched policy is the only option here that cannot be undone by
  > someone else's packaging change.

  With `logqueries` on, the query log confirms which path ran: `config … is
  NXDOMAIN` means answered locally and never forwarded, as against
  `forwarded … to`.
- The set is keyed on the UCI section id, so editing policies can change the
  set name.

> **This is a legitimate configuration, not a broken one** — but on stock
> OpenWrt it does not work until you deal with `rfc6761.conf` above. Once DNS is
> wired correctly — `server=/onion/127.0.0.1#9053` actually reaching Tor, and
> Tor's answer coming back intact — the virtual address lands in the set and
> everything works.
>
> **pbr does not warn about a `dest_addr`, deliberately.** Whether one works
> depends on DNS reaching Tor, which pbr has no way to observe, so a warning
> would fire exactly as loudly on a correct setup as on a broken one. It is
> documented here instead. pbr does warn about `src_port`, `dest_port`, `proto`
> and `chain`, which are discarded in every case.

### Every way mode B fails quietly

Grouped by where in the chain it breaks. None of these announces itself — the
policy loads without error and the rules look correct in `nft list` throughout.
Mode A is immune to 2–5 outright, because the query never leaves the packet
path — and needs no set at all, so 1 does not apply either.

| # | Breaks at | Pitfall | How it shows / what to check |
| - | --------- | ------- | ---------------------------- |
| 1 | No set is built at all | `resolver_set` is not `dnsmasq.nftset`, or dnsmasq lacks nftset support | pbr resolves the name itself and fails: `ERROR: Failed to resolve 'onion'`. `uci get pbr.config.resolver_set`; `dnsmasq --version \| grep nftset` |
| 2 | DNS not routed to Tor | No `server=/onion/127.0.0.1#9053` at all | upstreams answer NXDOMAIN, or hijack the TLD with a public address |
| 3 | DNS blocked before Tor | OpenWrt's `rfc6761.conf` ships `server=/onion/` | both log lines appear, local wins — see above |
| 4 | DNS blocked before Tor | A blocklist writing addressless `server=/domain/` through `serversfile` (adblock and friends) | `grep -n onion /var/run/*/dnsmasq.servers`; stop the service, restart dnsmasq, re-test |
| 5 | DNS never reaches dnsmasq | Client resolves for itself — browser DoH/DoT, or hardcoded DNS | the client resolves the name fine, yet the set stays empty; check the browser's secure-DNS setting |
| 6 | Tor produces no answer | `AutomapHostsOnResolve` missing from torrc | `nslookup -port=9053 <name>.onion 127.0.0.1` returns nothing |
| 7 | Wrong redirect ports | pbr read only `/etc/tor/torrc`, only in `address:port` form | redirect points at a port nothing is listening on |
| 8 | Set poisoned | Wrong answers land in the set and **never expire** — pbr sets no timeout on these entries | `nft list set …` shows public addresses; only `service pbr restart` clears them, and until then they push unrelated traffic into Tor |
| 9 | IPv6 half of the answer | Tor returns an AAAA virtual address too; `TransPort` bound only to `0.0.0.0` | intermittent — depends on whether the client picks A or AAAA |
| 10 | Port coverage | Only 53, 80 and 443 are ever redirected | an onion service on any other port is never torified, whatever `dest_addr` says |

Items 3 and 4 are the same mechanism — an addressless `server=/domain/` meaning
"answer locally, never forward" — from two different sources. Confirming which
one is in play matters, because the fixes are unrelated.

**The practical rule:** for Tor, match on source and leave `dest_addr` empty.

Both modes can work for `.onion`, but they depend on different things. Mode B
needs dnsmasq to forward `.onion` to Tor with nothing overriding it — which on
stock OpenWrt means removing the `rfc6761.conf` block first, a dependency pbr
cannot see or verify. Mode A redirects the client's port 53 traffic to Tor's
DNSPort at the packet level, so the query never reaches dnsmasq at all and none
of its `.onion` handling applies: Tor resolves the name natively, hands back a
virtual address, and the same policy's rules carry the traffic. One step, no set
to populate, and nothing outside pbr that can silently break it.

The tradeoff is that mode A sends *all* of that client's DNS to Tor, so any
local filtering (adblock and friends) no longer applies to it. A domain-matched
policy remains the right tool for ordinary destinations.

---

## When it doesn't work

**Start here.** Run both, and compare — this one pair localises almost every
`.onion` failure to one side or the other:

```sh
nslookup <name>.onion 127.0.0.1            # via dnsmasq
nslookup -port=9053 <name>.onion 127.0.0.1 # straight from Tor
```

If the second returns a virtual address and the first does not, Tor is fine and
dnsmasq is losing the answer — go to the first row below. If neither works, the
problem is in Tor or torrc.

| Symptom | Likely cause | Check |
| ------- | ------------ | ----- |
| Tor answers on :9053, dnsmasq returns NXDOMAIN | dnsmasq is answering `.onion` locally instead of forwarding — either no `server=/onion/…` is set, or something overrides it | `logread \| grep -E "locally-known\|for domain"` — want `for domain onion`, not `locally-known … onion` |
| `server=/onion/…` is set but the log *also* says `locally-known … onion` | OpenWrt's `/usr/share/dnsmasq/rfc6761.conf` carries an addressless `server=/onion/`, which wins | `grep -n onion /usr/share/dnsmasq/rfc6761.conf` — comment the line out, or use a source-matched policy to bypass dnsmasq entirely |
| Set holds public addresses instead of `172.x`/`10.x` | Something other than Tor is answering `.onion` lookups; pbr stores whatever DNS returns, and these entries never expire | `nft list set inet fw4 pbr_tor_4_dst_ip_<uid>`; clear with `service pbr restart` once DNS is fixed |
| Client resolves `.onion` but nothing is torified | Client is bypassing dnsmasq — browser DoH/DoT or its own resolver — so the set is never populated | disable secure DNS in the browser and re-test; the set only ever fills from dnsmasq |
| `.onion` fails, everything else torified | Domain-matched policy whose set is empty | `nft list set inet fw4 pbr_tor_4_dst_ip_<uid>` |
| `ERROR: Failed to resolve 'onion'` | The resolver/nftset path is off, so pbr tried ordinary DNS — which can never resolve a `.onion` name | `uci get pbr.config.resolver_set` |
| IPv4 works, but some clients still fail | Tor returns an IPv6 virtual address too; TransPort bound only to `0.0.0.0` has nothing listening on IPv6 | see the IPv6 note below |
| Redirect fires but nothing loads | Stale virtual address — Tor restarted since the answer was cached | `logread -e tor`, then flush client + dnsmasq caches |
| Nothing is torified at all | Tor not detected — no rules were written | `nft list chain inet fw4 pbr_dstnat` |
| Connections refused on 80/443 | Redirecting to a port Tor isn't listening on | `netstat -ltnp \| grep tor` |
| Works on default ports, breaks on custom | torrc uses the bare form, so pbr fell back to 9053/9040 | `grep -E 'DNSPort\|TransPort' /etc/tor/torrc` |
| Ports set in an include file are ignored | pbr reads only `/etc/tor/torrc`, never `%include`d files or `conf.d` | `grep -rE 'DNSPort\|TransPort' /etc/tor/` — if the hits are outside `torrc`, pbr never saw them |
| Some apps bypass Tor entirely | Their traffic isn't on 53, 80 or 443 | expected — see the five rules above |

> **torrc syntax matters more than it should.** pbr only recognises the
> `address:port` form — `DNSPort 0.0.0.0:9053`. A bare `DNSPort 9153` does not
> parse, and pbr silently falls back to `9053`, redirecting every DNS query to a
> port nothing is listening on. Written with the default numbers the bare form
> still appears to work, which is what makes this one hard to spot.

### A working reference torrc

```
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 172.16.0.0/12
TransPort 0.0.0.0:9040
DNSPort 0.0.0.0:9053
```

This matches what OpenWrt's Tor client guide sets, and what the pbr docs show,
so following both does not produce a mismatch. Tor's own default is different
(`127.192.0.0/10`) — see the caution above about not assuming the range.

`AutomapHostsOnResolve` is not optional. Without it Tor's DNSPort will not
invent an address for a `.onion` name, so there is nothing for the traffic rules
to match and onion addresses cannot resolve at all.

### Two valid dnsmasq designs

OpenWrt's [Tor client guide](https://openwrt.org/docs/guide-user/services/tor/client)
routes **all** DNS through Tor — it replaces the server list outright and turns
off upstream resolution:

```sh
uci set dhcp.@dnsmasq[0].noresolv="1"
uci set dhcp.@dnsmasq[0].localuse="0"
uci set dhcp.@dnsmasq[0].rebind_protection="0"
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server="127.0.0.1#9053"
uci add_list dhcp.@dnsmasq[0].server="::1#9053"
```

paired with `AutomapHostsSuffixes .` in torrc, so Tor maps *every* name to a
virtual address. Simple, but everything on the router resolves through Tor.

The alternative is to scope Tor to `.onion` only and leave normal DNS alone:

```sh
uci add_list dhcp.@dnsmasq[0].server="/onion/127.0.0.1#9053"
# ... regular upstream servers stay in the list
uci set dhcp.@dnsmasq[0].allservers="1"
```

This is sound, and `all-servers` does **not** leak `.onion` to the public
resolvers: dnsmasq picks the most specific domain match, and since 2.53 it
distributes a query to all servers *available for that domain* — for `.onion`
that set contains only the Tor server. Ordinary lookups keep using the normal
upstreams and any local filtering.

Note the port separator is `#`, not `:` — `127.0.0.1#9053`.

Both designs hit the `rfc6761.conf` block described above, and neither guide
mentions it.

### If IPv6 is enabled, bind TransPort on IPv6 too

Tor's DNSPort answers a `.onion` lookup with **both** an IPv4 and an IPv6
virtual address. With `ipv6_enabled`, pbr writes the matching
`ip6 daddr @pbr_tor_6_dst_ip_<uid> … redirect to :9040` rule — so a client that
prefers IPv6 gets redirected to TransPort *on IPv6*. A torrc binding only
`0.0.0.0` has nothing listening there, and the connection is refused even
though IPv4 would have worked. Either add the IPv6 listeners:

```
TransPort [::]:9040
DNSPort [::]:9053
```

or disable IPv6 in pbr. Note this failure is intermittent by nature — it
depends on whether the client picks the A or the AAAA record.

---

## Quick reference

| Question | Answer |
| -------- | ------ |
| Does Tor need a routing table? | **No** — pure NAT redirect |
| Does it get a firewall mark? | **No** — field stays empty |
| Does it appear in the WebUI interface list? | **Yes** — when torrc is present |
| Are ports other than 53/80/443 covered? | **No** |
| Should `dest_port` or `proto` be set on the policy? | **No** — pbr clears them |
| Should `src_port` be set? | **No** — produces malformed rules |
| Should `dest_addr` be set? | **Not normally** — see mode B |
| Does a domain `dest_addr` need anything else? | **Yes** — `resolver_set = dnsmasq.nftset`, or pbr resolves it itself and fails |
| Does `dest_addr = onion` work on stock OpenWrt? | **No** — `rfc6761.conf` blocks the lookup until you remove it |
| Is a Tor problem ever a pbr version problem? | **No** — the Tor path is unchanged 1.1.6 → 1.2.3 |
