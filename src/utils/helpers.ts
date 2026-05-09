export function safeRelease(...lockables) {
	for (const l of lockables) { try { l?.releaseLock?.() } catch (_) {} }
}

export function safeClose(...closeables) {
	for (const c of closeables) { try { c?.close?.() } catch (_) {} }
}

export function escapeHTML(str) {
	return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function maskSensitiveInfo(text, prefixLen = 3, suffixLen = 2) {
	if (!text || typeof text !== 'string') return text;
	if (text.length <= prefixLen + suffixLen) return text;
	const prefix = text.slice(0, prefixLen);
	const suffix = text.slice(-suffixLen);
	const starCount = text.length - prefixLen - suffixLen;
	return `${prefix}${'*'.repeat(starCount)}${suffix}`;
}

export const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
