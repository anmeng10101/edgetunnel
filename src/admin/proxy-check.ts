import { TlsClient } from '../protocols/tls.js';
import { getProxyDefaultPort, getSOCKS5Account } from '../protocols/proxy-address.js';
import { joinBytes } from '../utils/bytes.js';

export async function checkProxyConnectivity(proxyProtocol, proxyParams, connectors) {
	const startTime = Date.now();
	try {
		const parsedProxyAddress = await getSOCKS5Account(proxyParams, getProxyDefaultPort(proxyProtocol));
		const { username, password, hostname, port } = parsedProxyAddress;
		const fullProxyParams = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
		const proxyConnectors = connectors.createConnectors(parsedProxyAddress);
		try {
			const detection = await detectProxyLocation(proxyProtocol, parsedProxyAddress, proxyConnectors);
			return {
				parsedProxyAddress,
				response: { success: true, proxy: proxyProtocol + "://" + fullProxyParams, ...detection, responseTime: Date.now() - startTime }
			};
		} catch (error) {
			return {
				parsedProxyAddress,
				response: { success: false, error: error.message, proxy: proxyProtocol + "://" + fullProxyParams, responseTime: Date.now() - startTime }
			};
		}
	} catch (err) {
		return {
			parsedProxyAddress: null,
			response: { success: false, error: err.message, proxy: proxyProtocol + "://" + proxyParams, responseTime: Date.now() - startTime }
		};
	}
}

async function detectProxyLocation(proxyProtocol, parsedProxyAddress, connectors) {
	const { socks5Connect, turnConnect, sstpConnect, httpsConnect, httpConnect, isIPHostname } = connectors;
	const detectHost = 'cloudflare.com';
	const detectPort = 443;
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tcpSocket = null;
	let tlsSocket = null;

	try {
		tcpSocket = proxyProtocol === 'socks5'
			? await socks5Connect(detectHost, detectPort, new Uint8Array(0))
			: proxyProtocol === 'turn'
				? await turnConnect(parsedProxyAddress, detectHost, detectPort)
				: proxyProtocol === 'sstp'
					? await sstpConnect(parsedProxyAddress, detectHost, detectPort)
					: (proxyProtocol === 'https' && isIPHostname(parsedProxyAddress.hostname)
						? await httpsConnect(detectHost, detectPort, new Uint8Array(0))
						: await httpConnect(detectHost, detectPort, new Uint8Array(0), proxyProtocol === 'https'));
		if (!tcpSocket) throw new Error('cannotConnectToProxy');

		tlsSocket = new TlsClient(tcpSocket, { serverName: detectHost, insecure: false });
		await tlsSocket.handshake();
		await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${detectHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
		const traceResponse = await readTraceResponse(tlsSocket, decoder);
		const ip = traceResponse.match(/(?:^|\n)ip=(.*)/)?.[1];
		const loc = traceResponse.match(/(?:^|\n)loc=(.*)/)?.[1];
		if (!ip || !loc) throw new Error('proxyDetectInvalidResponse');
		return { ip, loc };
	} finally {
		try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
	}
}

async function readTraceResponse(tlsSocket, decoder) {
	let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
	const maxResponseBytes = 64 * 1024;
	while (responseBuffer.length < maxResponseBytes) {
		const value = await tlsSocket.read();
		if (!value) break;
		if (value.byteLength === 0) continue;
		responseBuffer = joinBytes(responseBuffer, value);
		if (headerEndIndex === -1) {
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) {
				headerEndIndex = crlfcrlf + 4;
				const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
				const statusLine = headers.split('\r\n')[0] || '';
				const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
				const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
				if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`proxyDetectRequestFailed: ${statusLine || 'invalidResponse'}`);
				const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
				if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
				chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
			}
		}
		if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
		if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
	}
	if (headerEndIndex === -1) throw new Error('proxyDetectHeaderTooLong');
	return decoder.decode(responseBuffer);
}
