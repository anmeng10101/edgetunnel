import { dataToUint8Array, joinBytes } from '../utils/bytes.js';
import { safeRelease } from '../utils/helpers.js';
import type { LogFn } from '../types.js';

export function createWebSocketTransport({ log = () => {} }: { log?: LogFn } = {}) {
	function closeSocketQuietly(socket) {
		try {
			if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
				socket.close();
			}
		} catch (error) { log(`[WebSocket] closeException: ${error.message}`) }
	}

	async function WebSocketsendAndWait(webSocket, payload) {
		const sendResult = webSocket.send(payload);
		if (sendResult && typeof sendResult.then === 'function') await sendResult;
	}

	async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
		let header = headerData, hasData = false, reader, useBYOB = false;
		const BYOBbufferSize = 512 * 1024, BYOBsingleReadLimit = 64 * 1024, BYOBhighThroughputThreshold = 50 * 1024 * 1024;
		const normalFlowAggThreshold = 128 * 1024, normalFlowFlushInterval = 2;
		const BYOBslowFlushInterval = 20, BYOBfastFlushInterval = 2, BYOBsafeThreshold = BYOBbufferSize - BYOBsingleReadLimit;

		const sendChunk = async (chunk) => {
			if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
			if (header) {
				const merged = new Uint8Array(header.length + chunk.byteLength);
				merged.set(header, 0); merged.set(chunk, header.length);
				await WebSocketsendAndWait(webSocket, merged.buffer);
				header = null;
			} else await WebSocketsendAndWait(webSocket, chunk);
		};

		try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
		catch (e) { reader = remoteSocket.readable.getReader() }

		try {
			if (!useBYOB) {
				let pendingChunks = [], pendingBytes = 0, flushtimer = null, flushtask = null;
				const flush = async () => {
					if (flushtask) return flushtask;
					flushtask = (async () => {
						if (flushtimer) { clearTimeout(flushtimer); flushtimer = null }
						if (pendingBytes <= 0) return;
						const chunks = pendingChunks, bytes = pendingBytes;
						pendingChunks = []; pendingBytes = 0;
						const payload = chunks.length === 1 ? chunks[0] : joinBytes(...chunks);
						if (payload.byteLength || bytes > 0) await sendChunk(payload);
					})().finally(() => { flushtask = null });
					return flushtask;
				};
				const pushNormalFlowChunk = async (chunk) => {
					const bytes = dataToUint8Array(chunk);
					if (!bytes.byteLength) return;
					pendingChunks.push(bytes);
					pendingBytes += bytes.byteLength;
					if (pendingBytes >= normalFlowAggThreshold) {
						await flush();
						if (pendingBytes >= normalFlowAggThreshold) await flush();
					} else if (!flushtimer) {
						flushtimer = setTimeout(() => { flush().catch(() => closeSocketQuietly(webSocket)) }, normalFlowFlushInterval);
					}
				};
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					hasData = true;
					await pushNormalFlowChunk(value);
				}
				await flush();
			} else {
				let mainBuf = new ArrayBuffer(BYOBbufferSize), offset = 0, totalBytes = 0;
				let flushintervalMs = BYOBfastFlushInterval, flushtimer = null, waitFlushRecover = null;
				let reading = false, readingPendingFlush = false;

				const flush = async () => {
					if (reading) { readingPendingFlush = true; return }
					try {
						if (offset > 0) { const p = new Uint8Array(mainBuf.slice(0, offset)); offset = 0; await sendChunk(p) }
					} finally {
						readingPendingFlush = false;
						if (flushtimer) { clearTimeout(flushtimer); flushtimer = null }
						if (waitFlushRecover) { const r = waitFlushRecover; waitFlushRecover = null; r() }
					}
				};

				while (true) {
					reading = true;
					const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, BYOBsingleReadLimit));
					reading = false;
					if (done) break;
					if (!value || value.byteLength === 0) { if (readingPendingFlush) await flush(); continue }
					hasData = true;
					mainBuf = value.buffer;
					const len = value.byteLength;

					if (value.byteOffset !== offset) {
						log(`[BYOB] offsetException: expected=${offset}, actual=${value.byteOffset}`);
						await sendChunk(new Uint8Array(value.buffer, value.byteOffset, len).slice());
						mainBuf = new ArrayBuffer(BYOBbufferSize); offset = 0; totalBytes = 0;
						continue;
					}

					if (len < BYOBsingleReadLimit) {
						flushintervalMs = BYOBfastFlushInterval;
						if (len < 4096) totalBytes = 0;
						if (offset > 0) { offset += len; await flush() }
						else await sendChunk(value.slice());
					} else {
						totalBytes += len; offset += len;
						if (!flushtimer) flushtimer = setTimeout(() => { flush().catch(() => closeSocketQuietly(webSocket)) }, flushintervalMs);
						if (readingPendingFlush) await flush();
						if (offset > BYOBsafeThreshold) {
							if (totalBytes > BYOBhighThroughputThreshold) flushintervalMs = BYOBslowFlushInterval;
							await new Promise(r => { waitFlushRecover = r });
						}
					}
				}
				reading = false;
				await flush();
				if (flushtimer) { clearTimeout(flushtimer); flushtimer = null }
			}
		} catch (err) { closeSocketQuietly(webSocket) }
		finally { try { reader.cancel() } catch (e) { } safeRelease(reader) }
		if (!hasData && retryFunc) await retryFunc();
	}

	return { closeSocketQuietly, WebSocketsendAndWait, connectStreams };
}
