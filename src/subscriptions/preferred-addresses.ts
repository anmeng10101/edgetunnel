import { normalizeToArray } from '../utils/normalization.js';

export function identifyISP(request) {
	const cf = request?.cf;
	const ASNispMapping = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const ispKeywordMapping = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const orgName = String(cf?.asOrganization || '').toLowerCase();
	const matchedISP = ispKeywordMapping.find(({ pattern }) => pattern.test(orgName))?.code;
	return matchedISP || ASNispMapping[String(cf?.asn || '')] || 'cf';
}

export async function generateRandomIP(request, count = 16, specifiedPort = -1, TLS = true) {
	const url = new URL(request.url);
	const queryParamISP = String(url.searchParams.get('asOrg') || '').toLowerCase();
	const ispFileIdentifier = ['ct', 'cu', 'cmcc', 'cf'].includes(queryParamISP) ? queryParamISP : identifyISP(request);
	const ispNameMapping = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = ispFileIdentifier === 'cf' ? 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt' : `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${ispFileIdentifier}.txt`;
	const cfname = ispNameMapping[ispFileIdentifier] || 'CF官方优选';
	const cfport = TLS ? [443, 2053, 2083, 2087, 2096, 8443] : [80, 8080, 8880, 2052, 2082, 2086, 2095];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await normalizeToArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const TLSport = [443, 2053, 2083, 2087, 2096, 8443];
	const NOTLSport = [80, 2052, 2082, 2086, 2095, 8080];

	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const targetPort = specifiedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: (TLS ? specifiedPort : (NOTLSport[TLSport.indexOf(Number(specifiedPort))] ?? specifiedPort));
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

export async function getSubGenData(subGenHOST) {
	let preferredIP = [], otherNodeLinks = '', formatHOST = subGenHOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formatHOST)) formatHOST = `https://${formatHOST}`;

	try {
		const url = new URL(formatHOST);
		formatHOST = url.origin;
	} catch (error) {
		preferredIP.push(`127.0.0.1:1234#${subGenHOST}subGenFormatError:${error.message}`);
		return [preferredIP, otherNodeLinks];
	}

	const subGenURL = `${formatHOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(subGenURL, {
			headers: { 'User-Agent': 'v2rayN/edgetunnel' }
		});

		if (!response.ok) {
			preferredIP.push(`127.0.0.1:1234#${subGenHOST}subGenException:${response.statusText}`);
			return [preferredIP, otherNodeLinks];
		}

		const subGenReturnedContent = atob(await response.text());
		const subLineList = subGenReturnedContent.includes('\r\n')
			? subGenReturnedContent.split('\r\n')
			: subGenReturnedContent.split('\n');

		for (const lineContent of subLineList) {
			if (!lineContent.trim()) continue;
			if (lineContent.includes('00000000-0000-4000-8000-000000000000') && lineContent.includes('example.com')) {
				const addrMatch = lineContent.match(/:\/\/[^@]+@([^?]+)/);
				if (addrMatch) {
					let addrPort = addrMatch[1], remark = '';
					const remarkMatch = lineContent.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
					preferredIP.push(addrPort + remark);
				}
			} else {
				otherNodeLinks += lineContent + '\n';
			}
		}
	} catch (error) {
		preferredIP.push(`127.0.0.1:1234#${subGenHOST}subGenException:${error.message}`);
	}

	return [preferredIP, otherNodeLinks];
}

export async function requestPreferredAPI(urls, defaultPort = '443', timeoutDuration = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), proxyIPPool = new Set();
	let subLinkPlaintextContent = '';
	await Promise.allSettled(urls.map(async (url) => {
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const APIremarkName = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const preferredIPAsProxyIP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [preferredIP, otherNodeLinks] = await getSubGenData(urlWithoutHash);
				if (APIremarkName) {
					for (const ip of preferredIP) {
						const processedIP = ip.includes('#')
							? `${ip} [${APIremarkName}]`
							: `${ip}#[${APIremarkName}]`;
						results.add(processedIP);
						if (preferredIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of preferredIP) {
						results.add(ip);
						if (preferredIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				}
				if (otherNodeLinks && typeof otherNodeLinks === 'string' && APIremarkName) {
					const processedLinkContent = otherNodeLinks.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subLinkPlaintextContent += processedLinkContent;
				} else if (otherNodeLinks && typeof otherNodeLinks === 'string') {
					subLinkPlaintextContent += otherNodeLinks;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeoutDuration);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				let decoders = ['utf-8', 'gb2312'];
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8'];
				}

				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							continue;
						}
					} catch (e) {
						continue;
					}
				}

				if (!decodeSuccess) {
					text = await response.text();
				}

				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			let preprocessSubPlaintext = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					preprocessSubPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (preprocessSubPlaintext.split('#')[0].includes('://')) {
				if (APIremarkName) {
					const processedLinkContent = preprocessSubPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subLinkPlaintextContent += processedLinkContent + '\n';
				} else {
					subLinkPlaintextContent += preprocessSubPlaintext + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					if (APIremarkName) {
						const processedIP = ipItem.includes('#')
							? `${ipItem} [${APIremarkName}]`
							: `${ipItem}#[${APIremarkName}]`;
						results.add(processedIP);
					} else {
						results.add(ipItem);
					}
					if (preferredIPAsProxyIP) proxyIPPool.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IPaddress') && headers.includes('port') && headers.includes('dataCenter')) {
					const ipIdx = headers.indexOf('IPaddress'), portIdx = headers.indexOf('port');
					const remarkIdx = headers.indexOf('country') > -1 ? headers.indexOf('country') :
						headers.indexOf('city') > -1 ? headers.indexOf('city') : headers.indexOf('dataCenter');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						if (APIremarkName) {
							const processedIP = `${ipItem} [${APIremarkName}]`;
							results.add(processedIP);
						} else {
							results.add(ipItem);
						}
						if (preferredIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('latency')) && headers.some(h => h.includes('downloadSpeed'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('latency'));
					const speedIdx = headers.findIndex(h => h.includes('downloadSpeed'));
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CFpreferred ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						if (APIremarkName) {
							const processedIP = `${ipItem} [${APIremarkName}]`;
							results.add(processedIP);
						} else {
							results.add(ipItem);
						}
						if (preferredIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	const LINKarray = subLinkPlaintextContent.trim() ? [...new Set(subLinkPlaintextContent.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINKarray, [], Array.from(proxyIPPool)];
}
