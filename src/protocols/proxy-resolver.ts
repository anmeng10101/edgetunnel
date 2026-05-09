import { normalizeToArray } from '../utils/normalization.js';
import type { DoHAnswer, LogFn } from '../types.js';

export function createProxyResolver({ dohQuery, log = () => {} }: { dohQuery: (domain: string, recordType: string, server?: string) => Promise<DoHAnswer[]>; log?: LogFn }) {
	let cachedProxyIP;
	let cachedProxyResolveArray;

	return async function resolveProxyAddresses(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
		if (!cachedProxyIP || !cachedProxyResolveArray || cachedProxyIP !== proxyIP) {
			proxyIP = proxyIP.toLowerCase();

			function parseProxyAddressEntry(str) {
				let address = str, port = 443;
				if (str.includes(']:')) {
					const parts = str.split(']:');
					address = parts[0] + ']';
					port = parseInt(parts[1], 10) || port;
				} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
					const colonIndex = str.lastIndexOf(':');
					address = str.slice(0, colonIndex);
					port = parseInt(str.slice(colonIndex + 1), 10) || port;
				}
				return [address, port];
			}

			function parseTXTProxyRecord(txtData) {
				return txtData.flatMap(data => {
					if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
					return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
				}).map(prefix => parseProxyAddressEntry(prefix));
			}

			const proxyIPArray = await normalizeToArray(proxyIP);
			let allProxyArray = [];
			const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
			const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

			for (const singleProxyIP of proxyIPArray) {
				let [address, port] = parseProxyAddressEntry(singleProxyIP);

				if (singleProxyIP.includes('.tp')) {
					const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
					if (tpMatch) port = parseInt(tpMatch[1], 10);
				}

				if (ipv4Regex.test(address) || ipv6Regex.test(address)) {
					log(`[proxyResolve] ${address} asIPAddress，directUse`);
					allProxyArray.push([address, port]);
					continue;
				}

				const [txtRecords, aRecords] = await Promise.all([
					dohQuery(address, 'TXT'),
					dohQuery(address, 'A')
				]);

				const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
				const txtAddresses = parseTXTProxyRecord(txtData);
				if (txtAddresses.length > 0) {
					log(`[proxyResolve] ${address} using TXT record, total ${txtAddresses.length}resultsCount`);
					allProxyArray.push(...txtAddresses);
					continue;
				}

				const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
				if (ipv4List.length > 0) {
					log(`[proxyResolve] ${address} no TXT records, using A record, total ${ipv4List.length}resultsCount`);
					allProxyArray.push(...ipv4List.map(ip => [ip, port]));
					continue;
				}

				const aaaaRecords = await dohQuery(address, 'AAAA');
				const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
				if (ipv6List.length > 0) {
					log(`[proxyResolve] ${address} no TXT/A records, using AAAA record, total ${ipv6List.length}resultsCount`);
					allProxyArray.push(...ipv6List.map(ip => [ip, port]));
				} else {
					log(`[proxyResolve] ${address} noTXTAAAAARecords，keepOriginalDomain`);
					allProxyArray.push([address, port]);
				}
			}
			const sortedArray = allProxyArray.sort((a, b) => a[0].localeCompare(b[0]));
			const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
			let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
			log(`[proxyResolve] randomSeed: ${randomSeed}\ntargetSite: ${targetRootDomain}`)
			const shuffled = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
			cachedProxyResolveArray = shuffled.slice(0, 8);
			log(`[proxyResolve] parseComplete totalNum: ${cachedProxyResolveArray.length}count\n${cachedProxyResolveArray.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
			cachedProxyIP = proxyIP;
		} else log(`[proxyResolve] readCache totalNum: ${cachedProxyResolveArray.length}count\n${cachedProxyResolveArray.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
		return cachedProxyResolveArray;
	}
}
