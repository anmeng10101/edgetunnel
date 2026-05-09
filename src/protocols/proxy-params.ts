import { getProxyDefaultPort, getSOCKS5Account, proxyProtocolDefaultPort } from './proxy-address.js';
import { base64SecretDecode } from '../subscriptions/transformers.js';
import type { ProxyProtocol, ProxyState } from '../types.js';

export async function parseProxyParams(url, uuid): Promise<ProxyState> {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	const state: ProxyState = {
		mySOCKS5Account: searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null,
		enableSOCKS5GlobalProxy: searchParams.has('globalproxy'),
	};

	const chainProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainProxyPathMatch) {
		try {
			const chainProxyPlaintext = base64SecretDecode(chainProxyPathMatch[1], uuid);
			const { type, ...chainProxyAddr } = JSON.parse(chainProxyPlaintext);
			const proxyProtocol = String(type).toLowerCase() as ProxyProtocol;
			if (!type || !proxyProtocolDefaultPort[proxyProtocol]) throw new Error('chainProxyTypeInvalid');
			if (!chainProxyAddr.hostname || !chainProxyAddr.port) throw new Error('chainProxyAddrMissing hostname or port');
			const parsedSocks5Address = {
				username: chainProxyAddr.username,
				password: chainProxyAddr.password,
				hostname: chainProxyAddr.hostname,
				port: Number(chainProxyAddr.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('chainProxyPortInvalid');
			return {
				mySOCKS5Account: '',
				proxyIP: 'chainProxy',
				enableProxyFallback: false,
				enableSOCKS5GlobalProxy: true,
				enableSOCKS5Proxy: proxyProtocol,
				parsedSocks5Address,
			};
		} catch (err) {
			console.error('parseChainProxyFailed:', err instanceof Error ? err.message : err);
		}
	}

	if (searchParams.get('socks5')) state.enableSOCKS5Proxy = 'socks5';
	else if (searchParams.get('http')) state.enableSOCKS5Proxy = 'http';
	else if (searchParams.get('https')) state.enableSOCKS5Proxy = 'https';
	else if (searchParams.get('turn')) state.enableSOCKS5Proxy = 'turn';
	else if (searchParams.get('sstp')) state.enableSOCKS5Proxy = 'sstp';

	const parseProxyURL = (value, forceGlobal = true) => {
		const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!match) return false;
		state.enableSOCKS5Proxy = match[1].toLowerCase() as ProxyProtocol;
		state.mySOCKS5Account = match[2].split('/')[0];
		if (forceGlobal) state.enableSOCKS5GlobalProxy = true;
		return true;
	};

	const setProxyIP = (value) => {
		state.proxyIP = value;
		state.enableSOCKS5Proxy = null;
		state.enableProxyFallback = false;
		return state;
	};

	const queryProxyIP = searchParams.get('proxyip');
	if (queryProxyIP !== null) {
		if (!parseProxyURL(queryProxyIP)) return setProxyIP(queryProxyIP);
	} else {
		let match = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (match) {
			const type = match[1].toLowerCase();
			state.enableSOCKS5Proxy = (type === 'sock' || type === 'socks' ? 'socks5' : type) as ProxyProtocol;
			state.mySOCKS5Account = match[2].split('/')[0];
			state.enableSOCKS5GlobalProxy = true;
		} else if ((match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const type = match[1].toLowerCase();
			state.mySOCKS5Account = match[2].split('/')[0];
			state.enableSOCKS5Proxy = type.includes('sstp') ? 'sstp' : (type.includes('turn') ? 'turn' : (type.includes('https') ? 'https' : (type.includes('http') ? 'http' : 'socks5')));
			if (type.startsWith('g')) state.enableSOCKS5GlobalProxy = true;
		} else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathProxyValue = extractPathValue(match[2]);
			if (!parseProxyURL(pathProxyValue)) return setProxyIP(pathProxyValue);
		}
	}

	if (!state.mySOCKS5Account) {
		state.enableSOCKS5Proxy = null;
		return state;
	}

	try {
		state.parsedSocks5Address = await getSOCKS5Account(state.mySOCKS5Account, getProxyDefaultPort(state.enableSOCKS5Proxy));
		if (searchParams.get('socks5')) state.enableSOCKS5Proxy = 'socks5';
		else if (searchParams.get('http')) state.enableSOCKS5Proxy = 'http';
		else if (searchParams.get('https')) state.enableSOCKS5Proxy = 'https';
		else if (searchParams.get('turn')) state.enableSOCKS5Proxy = 'turn';
		else if (searchParams.get('sstp')) state.enableSOCKS5Proxy = 'sstp';
		else state.enableSOCKS5Proxy = state.enableSOCKS5Proxy || 'socks5';
	} catch (err) {
		console.error('parseSOCKS5AddrFailed:', err instanceof Error ? err.message : err);
		state.enableSOCKS5Proxy = null;
	}
	return state;
}

function extractPathValue(value) {
	if (!value.includes('://')) {
		const slashIndex = value.indexOf('/');
		return slashIndex > 0 ? value.slice(0, slashIndex) : value;
	}
	const protocolSplit = value.split('://');
	if (protocolSplit.length !== 2) return value;
	const slashIndex = protocolSplit[1].indexOf('/');
	return slashIndex > 0 ? `${protocolSplit[0]}://${protocolSplit[1].slice(0, slashIndex)}` : value;
}
