import type { DoHAnswer, LogFn } from '../types.js';

const dohCache = new Map<string, { data: DoHAnswer[]; expiry: number }>();

export async function dohQuery(domain: string, recordType: string, dohServer = "https://cloudflare-dns.com/dns-query", log: LogFn = console.log) {
	const cacheKey = `${domain}:${recordType}:${dohServer}`;
	const cached = dohCache.get(cacheKey);
	if (cached && cached.expiry > Date.now()) {
		log(`[DoH] cache hit ${domain} ${recordType}`);
		return cached.data;
	}
	const startTime = performance.now();
	log(`[DoH] querying ${domain} ${recordType} via ${dohServer}`);
	try {
		const typeMap: Record<string, number> = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;

		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);

		const response = await fetch(dohServer, {
			method: 'POST',
			headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH] request failed ${domain} ${recordType} via ${dohServer} status:${response.status}`);
			return [];
		}

		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);

		const parseDomain = (pos: number): [string, number] => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseDomain(offset);
			offset = end + 4;
		}

		const answers: DoHAnswer[] = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDomain(offset);
			offset = nameEnd;
			const type = dv.getUint16(offset); offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				const [cname] = parseDomain(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}

		const minTTL = answers.length > 0 ? Math.max(Math.min(...answers.map(a => a.TTL)), 60) : 300;
		for (const [k, v] of dohCache) { if (v.expiry <= Date.now()) dohCache.delete(k); }
		dohCache.set(cacheKey, { data: answers, expiry: Date.now() + minTTL * 1000 });
		if (dohCache.size > 200) { dohCache.delete(dohCache.keys().next().value); }
		return answers;
	} catch (error) {
		const elapsed = (performance.now() - startTime).toFixed(2);
		console.error(`[DoH] query failed ${domain} ${recordType} via ${dohServer} ${elapsed}ms:`, error);
		return [];
	}
}
