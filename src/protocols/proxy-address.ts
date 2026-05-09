export const proxyProtocolDefaultPort = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };

export function getProxyDefaultPort(type) {
	return proxyProtocolDefaultPort[String(type || '').toLowerCase()] || 80;
}

const SOCKS5accountBase64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPv6bracketRegex = /^\[.*\]$/;

export function getSOCKS5Account(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5accountBase64Regex.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('invalid SOCKS addrFormat：authPartMustBe "username:password" inFormOf');

	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('invalid SOCKS addrFormat：portMustBeNumber');
	if (hostname.includes(":") && !IPv6bracketRegex.test(hostname)) throw new Error('invalid SOCKS addrFormat：IPv6 addrMustBeBracketed，if [2001:db8::1]');
	return { username, password, hostname, port };
}
