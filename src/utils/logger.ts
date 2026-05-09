import { maskSensitiveInfo } from './helpers.js';

export async function requestLogger(env, request, clientIP, requestType = "Get_SUB", configJSON, writeKVLog = true) {
	try {
		const now = new Date();
		const sanitizedURL = request.url.replace(/token=[^&]+/gi, 'token=***').replace(/uuid=[^&]+/gi, 'uuid=***').replace(/password=[^&]+/gi, 'password=***');
		const requestCf = request.cf || {};
		const logEntry = { TYPE: requestType, IP: maskSensitiveInfo(clientIP, 3, 0), ASN: `AS${requestCf.asn || '0'} ${requestCf.asOrganization || 'Unknown'}`, CC: `${requestCf.country || 'N/A'} ${requestCf.city || 'N/A'}`, URL: sanitizedURL, UA: request.headers.get('User-Agent') || 'Unknown', TIME: now.getTime() };
		writeKVLog = ['1', 'true'].includes(env.OFF_LOG) ? false : writeKVLog;
		if (!writeKVLog) return;
		let logArray = [];
		const existingLog = await env.KV.get('log.json'), kvSizeLimit = 4;
		if (existingLog) {
			try {
				logArray = JSON.parse(existingLog);
				if (!Array.isArray(logArray)) { logArray = [logEntry] }
				else if (requestType !== "Get_SUB") {
					const thirtyMinAgo = now.getTime() - 30 * 60 * 1000;
					if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === clientIP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= thirtyMinAgo)) return;
					logArray.push(logEntry);
					let serialized = JSON.stringify(logArray, null, 2);
					while (serialized.length > kvSizeLimit * 1024 * 1024 && logArray.length > 1) {
						logArray.splice(0, Math.max(1, Math.floor(logArray.length * 0.1)));
						serialized = JSON.stringify(logArray, null, 2);
					}
				} else {
					logArray.push(logEntry);
					let serialized = JSON.stringify(logArray, null, 2);
					while (serialized.length > kvSizeLimit * 1024 * 1024 && logArray.length > 1) {
						logArray.splice(0, Math.max(1, Math.floor(logArray.length * 0.1)));
						serialized = JSON.stringify(logArray, null, 2);
					}
				}
			} catch (e) { logArray = [logEntry] }
		} else { logArray = [logEntry] }
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) { console.error(`Log recording failed: ${error.message}`) }
}
