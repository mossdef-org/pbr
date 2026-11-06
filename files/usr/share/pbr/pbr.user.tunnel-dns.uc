// Resolves the domains of a policy through a resolver reached via the policy's interface,
// so lookups take the same path as the traffic (and geo-located CDNs answer accordingly).
// Adds server=/<domain>/<resolver>@<device> to the dnsmasq nftset file for every
// policy whose interface is listed below; other domains resolve as before.
// The map is keyed by the pbr/UCI interface name; its device is looked up when pbr starts.
// An entry that is not an address[#port], or an interface with no device at that point,
// is skipped with a warning, so a mistake only costs that interface its pinning.
// If the tunnel goes down later, lookups for its domains fail rather than leak.
// A server= entry for the same domain in /etc/config/dhcp would be used alongside,
// so remove it; a warning is logged when one is found.
// dnsmasq pins @device with IP_UNICAST_IF, which only steers the first route lookup; an
// output policy that marks the query (e.g. a router catch-all) makes the kernel reroute it by
// table and the pin is lost, so queries already routed out their device are left unmarked.
// Ordering: pbr runs user files after processing the policies (the dnsmasq file then holds
// this run's nftset lines) and before comparing that file's hash (so a change to the lines
// appended here restarts dnsmasq). If that order changed, this would break silently.

return function(api) {
	if (!api.compat || api.compat < 29) return;

	// interface: address[#port] of a resolver reachable through it, e.g. a VPN provider's in-tunnel DNS
	let resolvers = {
		// wg0: '10.0.0.1',
	};
	let dnsmasq_file = '/var/run/pbr.dnsmasq';

	if (!length(keys(resolvers))) return;
	let uci = require('uci').cursor();
	if (uci.get('pbr', 'config', 'resolver_set') != 'dnsmasq.nftset') return;

	let _warn = function(msg) {
		system([ 'logger', '-t', 'pbr', 'tunnel-dns: ' + msg ]);
	};
	let _is_domain = function(d) {
		return match(d, /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i) && !match(d, /^[0-9.]+$/);
	};

	// A bad address would reject pbr's whole ruleset or stop dnsmasq starting, and a
	// UCI name in place of the device would never match, so check both first.
	let ubus = require('ubus').connect();
	let targets = {};
	for (let iface, r in resolvers) {
		let m = match(r, /^([^#]+)(#([0-9]+))?$/);
		let addr = m ? iptoarr(m[1]) : null;
		let port = m ? +(m[3] || '53') : 0;
		if (!addr || port < 1 || port > 65535) {
			_warn(iface + ": '" + r + "' is not an address[#port]; skipped");
			continue;
		}
		let dev = ubus?.call('network.interface.' + iface, 'status')?.l3_device;
		if (!dev) {
			_warn(iface + ': no device (interface down or unknown); skipped');
			continue;
		}
		targets[iface] = { addr: arrtoip(addr), port, family: (length(addr) == 16) ? '6' : '4', dev };
	}
	ubus?.disconnect();
	if (!length(keys(targets))) return;

	let pinned = {};
	uci.foreach('dhcp', 'dnsmasq', function(s) {
		for (let v in ((type(s.server) == 'array') ? s.server : [ s.server ])) {
			let m = match(v || '', /^\/([^\/]+)\//);
			if (m) pinned[m[1]] = true;
		}
	});

	// First policy to claim a domain wins, as it does for the traffic.
	let seen = {};
	let lines = [];
	let used = {};
	uci.foreach('pbr', 'policy', function(s) {
		if (s.enabled == '0') return;
		let dest = (type(s.dest_addr) == 'array') ? join(' ', s.dest_addr) : (s.dest_addr || '');
		for (let d in split(trim(dest), /\s+/)) {
			if (!_is_domain(d) || seen[d]) continue;
			seen[d] = true;
			let t = targets[s.interface];
			if (!t) continue;
			push(lines, 'server=/' + d + '/' + t.addr + ((t.port != 53) ? '#' + t.port : '') +
				'@' + t.dev + ' # ' + s.name);
			used[s.interface] = t;
			if (pinned[d])
				_warn(d + ' also has a dhcp server entry; remove it, or answers will mix');
		}
	});

	if (!length(lines)) return;

	let pairs = { '4': [], '6': [] };
	for (let i, t in used)
		push(pairs[t.family], '"' + t.dev + '" . ' + t.addr + ' . ' + t.port);
	for (let fam in [ '4', '6' ]) {
		if (!length(pairs[fam])) continue;
		let rule = 'insert rule ' + api.table + ' pbr_output meta l4proto { tcp, udp } oifname . ' +
			(fam == '4' ? 'ip' : 'ip6') + ' daddr . th dport { ' + join(', ', pairs[fam]) + ' } return';
		(fam == '4') ? api.nft4(rule) : api.nft6(rule);
	}
	let f = require('fs').open(dnsmasq_file, 'a');
	if (!f) return;
	f.write(join('\n', lines) + '\n');
	f.close();
};
