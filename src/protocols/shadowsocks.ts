import { concatBytes, joinBytes } from '../utils/bytes.js';

export const supportedShadowsocksCiphers = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

export const SHADOWSOCKS_AEAD_TAG_LENGTH = 16, SHADOWSOCKS_NONCE_LENGTH = 12;
const shadowsocksSubkeyInfo = new TextEncoder().encode('ss-subkey');
const shadowsocksTextEncoder = new TextEncoder();
export const shadowsocksTextDecoder = new TextDecoder();
const shadowsocksMasterKeyCache = new Map();

function incrementShadowsocksNonce(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

export async function deriveShadowsocksMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (shadowsocksMasterKeyCache.has(cacheKey)) return shadowsocksMasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = shadowsocksTextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = joinBytes(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	shadowsocksMasterKeyCache.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { shadowsocksMasterKeyCache.delete(cacheKey); throw error }
}

export async function deriveShadowsocksSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = concatBytes(prev, shadowsocksSubkeyInfo, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

export async function encryptShadowsocksAead(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	incrementShadowsocksNonce(nonceCounter);
	return new Uint8Array(ct);
}

export async function decryptShadowsocksAead(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	incrementShadowsocksNonce(nonceCounter);
	return new Uint8Array(pt);
}
