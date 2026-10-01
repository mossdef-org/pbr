// Resolves the domains of a policy through a resolver reached via the policy's interface,
// so lookups take the same path as the traffic (and geo-located CDNs answer accordingly).
// Adds server=/<domain>/<resolver>@<interface> to the dnsmasq nftset file for every
// policy whose interface is listed below; other domains resolve as before.
// If the interface is down, lookups for its domains fail rather than leak.
// A server= entry for the same domain in /etc/config/dhcp would be used alongside,
// so remove it; a warning is logged when one is found.

return function(api) {
	if (!api.compat || api.compat < 29) return;

	// interface: resolver reachable through it, e.g. a VPN provider's in-tunnel DNS
	let resolvers = {
		// wg0: '10.0.0.1',
	};
	let dnsmasq_file = '/var/run/pbr.dnsmasq';

	if (!length(keys(resolvers))) return;
	let uci = require('uci').cursor();
	if (uci.get('pbr', 'config', 'resolver_set') != 'dnsmasq.nftset') return;

	let _is_domain = function(d) {
		return match(d, /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i) && !match(d, /^[0-9.]+$/);
	};

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
	uci.foreach('pbr', 'policy', function(s) {
		if (s.enabled == '0') return;
		let dest = (type(s.dest_addr) == 'array') ? join(' ', s.dest_addr) : (s.dest_addr || '');
		for (let d in split(trim(dest), /\s+/)) {
			if (!_is_domain(d) || seen[d]) continue;
			seen[d] = true;
			if (!resolvers[s.interface]) continue;
			push(lines, 'server=/' + d + '/' + resolvers[s.interface] + '@' + s.interface + ' # ' + s.name);
			if (pinned[d])
				system([ 'logger', '-t', 'pbr', 'tunnel-dns: ' + d + ' also has a dhcp server entry; remove it, or answers will mix' ]);
		}
	});

	if (!length(lines)) return;
	let f = require('fs').open(dnsmasq_file, 'a');
	if (!f) return;
	f.write(join('\n', lines) + '\n');
	f.close();
};
