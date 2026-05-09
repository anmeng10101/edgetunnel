import type {
	ByteSource,
	ConnectFn,
	LogFn,
	ParsedProtocolRequest,
	ProxyAddressEntry,
	ProxyConnector,
	ProxyState,
	ShadowsocksCipherConfig,
	SocketLike,
	TunneledProxyConnector,
	WebSocketBridge,
	XHTTPFirstPacket,
} from '../types.js';

interface TransportHandlerDeps {
	connect?: ConnectFn;
	safeRelease?: (...lockables: unknown[]) => void;
	safeClose?: (...closeables: unknown[]) => void;
	dataToUint8Array?: (value: ByteSource) => Uint8Array;
	joinBytes?: (...values: ByteSource[]) => Uint8Array;
	readXHTTPFirstPacket?: (reader: ReadableStreamDefaultReader, token: string) => Promise<XHTTPFirstPacket | null>;
	validDataLength?: (value: ByteSource) => number;
	isSpeedTestSite?: (hostname: string) => boolean;
	parseTrojanRequest?: (buffer: Uint8Array, passwordPlainText: string) => ParsedProtocolRequest;
	parseVLESSRequest?: (chunk: Uint8Array, token: string) => ParsedProtocolRequest;
	decryptShadowsocksAead?: (cryptoKey: CryptoKey, nonceCounter: Uint8Array, ciphertext: Uint8Array<ArrayBufferLike>) => Promise<Uint8Array>;
	encryptShadowsocksAead?: (cryptoKey: CryptoKey, nonceCounter: Uint8Array, plaintext: Uint8Array<ArrayBufferLike>) => Promise<Uint8Array>;
	shadowsocksAeadTagLength?: number;
	deriveShadowsocksMasterKey?: (passwordText: string, keyLen: number) => Promise<Uint8Array>;
	deriveShadowsocksSessionKey?: (config: ShadowsocksCipherConfig, masterKey: Uint8Array, salt: Uint8Array, usages: KeyUsage[]) => Promise<CryptoKey>;
	shadowsocksNonceLength?: number;
	supportedShadowsocksCiphers?: Record<string, ShadowsocksCipherConfig>;
	shadowsocksTextDecoder?: TextDecoder;
	socks5Connect?: ProxyConnector;
	httpConnect?: (targetHost: string, targetPort: number, initialData?: ByteSource, HTTPSproxy?: boolean) => Promise<SocketLike>;
	httpsConnect?: ProxyConnector;
	turnConnect?: TunneledProxyConnector;
	sstpConnect?: TunneledProxyConnector;
	isIPHostname?: (hostname: string) => boolean;
	resolveProxyAddresses?: (proxyIP: string, targetDomain?: string, UUID?: string) => Promise<ProxyAddressEntry[]>;
	getProxyState?: () => ProxyState;
	setCachedProxyArrayIndex?: (index: number) => void;
	closeSocketQuietly?: (socket: WebSocketBridge) => void;
	WebSocketsendAndWait?: (webSocket: WebSocketBridge, payload: unknown) => Promise<void>;
	connectStreams?: (remoteSocket: SocketLike, webSocket: WebSocketBridge, headerData?: ByteSource, retryFunc?: () => Promise<void>) => Promise<void>;
	log?: LogFn;
}

export function createTransportHandlers({
	connect,
	safeRelease,
	safeClose,
	dataToUint8Array,
	joinBytes,
	readXHTTPFirstPacket,
	validDataLength,
	isSpeedTestSite,
	parseTrojanRequest,
	parseVLESSRequest,
	decryptShadowsocksAead,
	encryptShadowsocksAead,
	shadowsocksAeadTagLength,
	deriveShadowsocksMasterKey,
	deriveShadowsocksSessionKey,
	shadowsocksNonceLength,
	supportedShadowsocksCiphers,
	shadowsocksTextDecoder,
	socks5Connect,
	httpConnect,
	httpsConnect,
	turnConnect,
	sstpConnect,
	isIPHostname,
	resolveProxyAddresses,
	getProxyState,
	setCachedProxyArrayIndex,
	closeSocketQuietly,
	WebSocketsendAndWait,
	connectStreams,
	log = () => { },
}: TransportHandlerDeps = {}) {
	const readProxyState = () => ({
		proxyIP: '',
		enableProxyFallback: true,
		enableSOCKS5Proxy: null,
		enableSOCKS5GlobalProxy: false,
		SOCKS5whitelist: [],
		parsedSocks5Address: {},
		cachedProxyArrayIndex: 0,
		...(getProxyState ? getProxyState() : {}),
	});
	const updateCachedProxyArrayIndex = setCachedProxyArrayIndex || (() => { });

	async function handleXHTTPTransport(request, yourUUID) {
		if (!request.body) return new Response('Bad Request', { status: 400 });
		const reader = request.body.getReader();
		const firstPacket = await readXHTTPFirstPacket(reader, yourUUID);
		if (!firstPacket) {
			safeRelease(reader)
			return new Response('Invalid request', { status: 400 });
		}
		if (isSpeedTestSite(firstPacket.hostname)) {
			safeRelease(reader)
			return new Response('Forbidden', { status: 403 });
		}
		if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
			safeRelease(reader)
			return new Response('UDP is not supported', { status: 400 });
		}

		const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
		let currentWriteSocket = null;
		let remoteWriter = null;
		const responseHeaders = new Headers({
			'Content-Type': 'application/octet-stream',
			'X-Accel-Buffering': 'no',
			'Cache-Control': 'no-store'
		});

		const releaseRemoteWriter = () => {
			if (remoteWriter) {
				safeRelease(remoteWriter)
				remoteWriter = null;
			}
			currentWriteSocket = null;
		};

		const getRemoteWriter = () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		};

		return new Response(new ReadableStream({
			async start(controller) {
				let isClosed = false;
				let udpRespHeader = firstPacket.respHeader;
				const trojanUDPContext = { cache: new Uint8Array(0) };
				const xhttpBridge: WebSocketBridge = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (isClosed) return;
						try {
							const chunk = data instanceof Uint8Array
								? data
								: data instanceof ArrayBuffer
									? new Uint8Array(data)
									: ArrayBuffer.isView(data)
										? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
										: new Uint8Array(data as ArrayBuffer | ArrayLike<number>);
							controller.enqueue(chunk);
						} catch (e) {
							isClosed = true;
							this.readyState = WebSocket.CLOSED;
						}
					},
					close() {
						if (isClosed) return;
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
						safeClose(controller)
					}
				};

				const writeToRemote = async (payload, allowRetry = true) => {
					const writer = getRemoteWriter();
					if (!writer) return false;
					try {
						await writer.write(payload);
						return true;
					} catch (err) {
						releaseRemoteWriter();
						if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
							await remoteConnWrapper.retryConnect();
							return await writeToRemote(payload, false);
						}
						throw err;
					}
				};

				try {
					if (firstPacket.isUDP) {
						if (firstPacket.rawData?.byteLength) {
							await forwardUdpPayload(firstPacket.protocol, firstPacket.rawData, xhttpBridge, udpRespHeader, trojanUDPContext);
							udpRespHeader = null;
						}
					} else {
						await forwardTcpConnection(firstPacket.hostname, firstPacket.port, firstPacket.rawData, xhttpBridge, firstPacket.respHeader, remoteConnWrapper, yourUUID);
					}

					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						if (firstPacket.isUDP) {
							await forwardUdpPayload(firstPacket.protocol, value, xhttpBridge, udpRespHeader, trojanUDPContext);
							udpRespHeader = null;
						} else {
							if (!(await writeToRemote(value))) throw new Error('Remote socket is not ready');
						}
					}

					if (!firstPacket.isUDP) {
						const writer = getRemoteWriter();
						if (writer) {
							try { await writer.close() } catch (e) { }
						}
					}
				} catch (err) {
					log(`[XHTTPforward] processFailed: ${err?.message || err}`);
					closeSocketQuietly(xhttpBridge);
				} finally {
					releaseRemoteWriter();
					safeRelease(reader)
				}
			},
			cancel() {
				releaseRemoteWriter();
				safeClose(remoteConnWrapper.socket)
				safeRelease(reader)
			}
		}), { status: 200, headers: responseHeaders });
	}

	async function handleGRPCTransport(request, yourUUID) {
		if (!request.body) return new Response('Bad Request', { status: 400 });
		const reader = request.body.getReader();
		const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
		let isDnsQuery = false;
		const trojanUDPContext = { cache: new Uint8Array(0) };
		let isTrojanProtocol = null;
		let currentWriteSocket = null;
		let remoteWriter = null;
		const grpcHeaders = new Headers({
			'Content-Type': 'application/grpc',
			'grpc-status': '0',
			'X-Accel-Buffering': 'no',
			'Cache-Control': 'no-store'
		});

		const downstreamCacheLimit = 64 * 1024;
		const downstreamFlushInterval = 20;

		return new Response(new ReadableStream({
			async start(controller) {
				let isClosed = false;
				let sendQueue = [];
				let queueByteCount = 0;
				let flushTimer = null;
				const grpcBridge: WebSocketBridge = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (isClosed) return;
						const chunk = data instanceof Uint8Array ? data : new Uint8Array(data as ArrayBuffer | ArrayLike<number>);
						const lenBytesarray = [];
						let remaining = chunk.byteLength >>> 0;
						while (remaining > 127) {
							lenBytesarray.push((remaining & 0x7f) | 0x80);
							remaining >>>= 7;
						}
						lenBytesarray.push(remaining);
						const lenBytes = new Uint8Array(lenBytesarray);
						const protobufLen = 1 + lenBytes.length + chunk.byteLength;
						const frame = new Uint8Array(5 + protobufLen);
						frame[0] = 0;
						frame[1] = (protobufLen >>> 24) & 0xff;
						frame[2] = (protobufLen >>> 16) & 0xff;
						frame[3] = (protobufLen >>> 8) & 0xff;
						frame[4] = protobufLen & 0xff;
						frame[5] = 0x0a;
						frame.set(lenBytes, 6);
						frame.set(chunk, 6 + lenBytes.length);
						sendQueue.push(frame);
						queueByteCount += frame.byteLength;
						if (queueByteCount >= downstreamCacheLimit) flushSendQueue();
						else if (!flushTimer) flushTimer = setTimeout(flushSendQueue, downstreamFlushInterval);
					},
					close() {
						if (this.readyState === WebSocket.CLOSED) return;
						flushSendQueue(true);
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
						safeClose(controller)
					}
				};

				const flushSendQueue = (force = false) => {
					if (flushTimer) {
						clearTimeout(flushTimer);
						flushTimer = null;
					}
					if ((!force && isClosed) || queueByteCount === 0) return;
					const out = new Uint8Array(queueByteCount);
					let offset = 0;
					for (const item of sendQueue) {
						out.set(item, offset);
						offset += item.byteLength;
					}
					sendQueue = [];
					queueByteCount = 0;
					try {
						controller.enqueue(out);
					} catch (e) {
						isClosed = true;
						grpcBridge.readyState = WebSocket.CLOSED;
					}
				};

				const closeConnection = () => {
					if (isClosed) return;
					flushSendQueue(true);
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
					if (flushTimer) clearTimeout(flushTimer);
					if (remoteWriter) {
						safeRelease(remoteWriter)
						remoteWriter = null;
					}
					currentWriteSocket = null;
					safeRelease(reader)
					safeClose(remoteConnWrapper.socket)
					safeClose(controller)
				};

				const releaseRemoteWriter = () => {
					if (remoteWriter) {
						safeRelease(remoteWriter)
						remoteWriter = null;
					}
					currentWriteSocket = null;
				};

				const writeToRemote = async (payload, allowRetry = true) => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return false;
					if (socket !== currentWriteSocket) {
						releaseRemoteWriter();
						currentWriteSocket = socket;
						remoteWriter = socket.writable.getWriter();
					}
					try {
						await remoteWriter.write(payload);
						return true;
					} catch (err) {
						releaseRemoteWriter();
						if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
							await remoteConnWrapper.retryConnect();
							return await writeToRemote(payload, false);
						}
						throw err;
					}
				};

				try {
					let pending = new Uint8Array(0);
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
						const merged = new Uint8Array(pending.length + currentChunk.length);
						merged.set(pending, 0);
						merged.set(currentChunk, pending.length);
						pending = merged;
						while (pending.byteLength >= 5) {
							const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
							const frameSize = 5 + grpcLen;
							if (pending.byteLength < frameSize) break;
							const grpcPayload = pending.slice(5, frameSize);
							pending = pending.slice(frameSize);
							if (!grpcPayload.byteLength) continue;
							let payload = grpcPayload;
							if (payload.byteLength >= 2 && payload[0] === 0x0a) {
								let shift = 0;
								let offset = 1;
								let varintvalid = false;
								while (offset < payload.length) {
									const current = payload[offset++];
									if ((current & 0x80) === 0) {
										varintvalid = true;
										break;
									}
									shift += 7;
									if (shift > 35) break;
								}
								if (varintvalid) payload = payload.slice(offset);
							}
							if (!payload.byteLength) continue;
							if (isDnsQuery) {
								await forwardUdpPayload(isTrojanProtocol ? 'trojan' : 'vless', payload, grpcBridge, null, trojanUDPContext);
								continue;
							}
							if (remoteConnWrapper.socket) {
								if (!(await writeToRemote(payload))) throw new Error('Remote socket is not ready');
							} else {
								let firstPacketBuffer;
								if (payload instanceof ArrayBuffer) firstPacketBuffer = payload;
								else if (ArrayBuffer.isView(payload)) firstPacketBuffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
								else firstPacketBuffer = new Uint8Array(payload).buffer;
								const firstPacketBytes = new Uint8Array(firstPacketBuffer);
								if (isTrojanProtocol === null) isTrojanProtocol = firstPacketBytes.byteLength >= 58 && firstPacketBytes[56] === 0x0d && firstPacketBytes[57] === 0x0a;
								if (isTrojanProtocol) {
									const parseResult = parseTrojanRequest(firstPacketBuffer, yourUUID);
									if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
									const { port, hostname, rawClientData, isUDP } = parseResult;
									log(`[gRPC] trojanFirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'is' : 'no'}`);
									if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
									if (isUDP) {
										isDnsQuery = true;
										if (validDataLength(rawClientData) > 0) await forwardUdpPayload('trojan', rawClientData, grpcBridge, null, trojanUDPContext);
									} else {
										await forwardTcpConnection(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID);
									}
								} else {
									isTrojanProtocol = false;
									const parseResult = parseVLESSRequest(firstPacketBuffer, yourUUID);
									if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
									const { port, hostname, rawIndex, version, isUDP } = parseResult;
									log(`[gRPC] vlessFirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'is' : 'no'}`);
									if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
									if (isUDP) {
										if (port !== 53) throw new Error('UDP is not supported');
										isDnsQuery = true;
									}
									const respHeader = new Uint8Array([version[0], 0]);
									grpcBridge.send(respHeader);
									const rawData = firstPacketBuffer.slice(rawIndex);
									if (isDnsQuery) {
										await forwardUdpPayload(isTrojanProtocol ? 'trojan' : 'vless', rawData, grpcBridge, null, trojanUDPContext);
									}
									else await forwardTcpConnection(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID);
								}
							}
						}
						flushSendQueue();
					}
				} catch (err) {
					log(`[gRPCforward] processFailed: ${err?.message || err}`);
				} finally {
					releaseRemoteWriter();
					closeConnection();
				}
			},
			cancel() {
				safeClose(remoteConnWrapper.socket)
				safeRelease(reader)
			}
		}), { status: 200, headers: grpcHeaders });
	}

	async function handleWebSocketTransport(request, yourUUID, url) {
		const WSsocketPair = new WebSocketPair();
		const [clientSock, serverSock] = Object.values(WSsocketPair);
		serverSock.accept();
		serverSock.binaryType = 'arraybuffer';
		let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
		let isDnsQuery = false;
		let isTrojanProtocol = null;
		const trojanUDPContext = { cache: new Uint8Array(0) };
		const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
		const SSmodeDisableEarlyData = !!url.searchParams.get('enc');
		let readCancelled = false;
		let readableStreamEnded = false;
		const readable = new ReadableStream({
			start(controller) {
				const isStreamClosedError = (err) => {
					const msg = err?.message || `${err || ''}`;
					return msg.includes('ReadableStream is closed') || msg.includes('The stream is closed') || msg.includes('already closed');
				};
				const safeEnqueue = (data) => {
					if (readCancelled || readableStreamEnded) return;
					try {
						controller.enqueue(data);
					} catch (err) {
						readableStreamEnded = true;
						if (!isStreamClosedError(err)) {
							try { controller.error(err) } catch (_) { }
						}
					}
				};
				const safeCloseStream = () => {
					if (readCancelled || readableStreamEnded) return;
					readableStreamEnded = true;
					try {
						controller.close();
					} catch (err) {
						if (!isStreamClosedError(err)) {
							try { controller.error(err) } catch (_) { }
						}
					}
				};
				const safeErrorStream = (err) => {
					if (readCancelled || readableStreamEnded) return;
					readableStreamEnded = true;
					try { controller.error(err) } catch (_) { }
				};
				serverSock.addEventListener('message', (event) => {
					safeEnqueue(event.data);
				});
				serverSock.addEventListener('close', () => {
					closeSocketQuietly(serverSock);
					safeCloseStream();
				});
				serverSock.addEventListener('error', (err) => {
					safeErrorStream(err);
					closeSocketQuietly(serverSock);
				});

				if (SSmodeDisableEarlyData || !earlyDataHeader) return;
				try {
					const binaryString = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
					const bytes = new Uint8Array(binaryString.length);
					for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
					safeEnqueue(bytes.buffer);
				} catch (error) {
					safeErrorStream(error);
				}
			},
			cancel() {
				readCancelled = true;
				readableStreamEnded = true;
				closeSocketQuietly(serverSock);
			}
		});
		let detectProtocolType = null, currentWriteSocket = null, remoteWriter = null;
		let sscontext = null, ssinitTasks = null;

		const releaseRemoteWriter = () => {
			if (remoteWriter) {
				safeRelease(remoteWriter)
				remoteWriter = null;
			}
			currentWriteSocket = null;
		};

		const writeToRemote = async (chunk, allowRetry = true) => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return false;

			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}

			try {
				await remoteWriter.write(chunk);
				return true;
			} catch (err) {
				releaseRemoteWriter();
				if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
					await remoteConnWrapper.retryConnect();
					return await writeToRemote(chunk, false);
				}
				throw err;
			}
		};

		const getSSContext = async () => {
			if (sscontext) return sscontext;
			if (!ssinitTasks) {
				ssinitTasks = (async () => {
					const requestEncryptMethod = (url.searchParams.get('enc') || '').toLowerCase();
					const preferredEncConfig = supportedShadowsocksCiphers[requestEncryptMethod] || supportedShadowsocksCiphers['aes-128-gcm'];
					const inboundCandidateEncConfig = [preferredEncConfig, ...Object.values(supportedShadowsocksCiphers).filter(c => c.method !== preferredEncConfig.method)];
					const inboundMasterKeyTaskCache = new Map();
					const getInboundMasterKeyTask = (config) => {
						if (!inboundMasterKeyTaskCache.has(config.method)) inboundMasterKeyTaskCache.set(config.method, deriveShadowsocksMasterKey(yourUUID, config.keyLen));
						return inboundMasterKeyTaskCache.get(config.method);
					};
					const inboundState = {
						buffer: new Uint8Array(0) as Uint8Array<ArrayBufferLike>,
						hasSalt: false,
						waitPayloadLength: null,
						decryptKey: null,
						nonceCounter: new Uint8Array(shadowsocksNonceLength),
						encryptConfig: null,
					};
					const initInboundDecryptState = async () => {
						const lengthCipherTotalLength = 2 + shadowsocksAeadTagLength;
						const maxSaltLength = Math.max(...inboundCandidateEncConfig.map(c => c.saltLen));
						const maxAlignScanBytes = 16;
						const maxScanOffset = Math.min(maxAlignScanBytes, Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLength + Math.min(...inboundCandidateEncConfig.map(c => c.saltLen)))));
						for (let offset = 0; offset <= maxScanOffset; offset++) {
							for (const encryptConfig of inboundCandidateEncConfig) {
								const initMinLength = offset + encryptConfig.saltLen + lengthCipherTotalLength;
								if (inboundState.buffer.byteLength < initMinLength) continue;
								const salt = inboundState.buffer.subarray(offset, offset + encryptConfig.saltLen);
								const lengthCipher = inboundState.buffer.subarray(offset + encryptConfig.saltLen, initMinLength);
								const masterKey = await getInboundMasterKeyTask(encryptConfig);
								const decryptKey = await deriveShadowsocksSessionKey(encryptConfig, masterKey, salt, ['decrypt']);
								const nonceCounter = new Uint8Array(shadowsocksNonceLength);
								try {
									const lengthPlain = await decryptShadowsocksAead(decryptKey, nonceCounter, lengthCipher);
									if (lengthPlain.byteLength !== 2) continue;
									const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
									if (payloadLength < 0 || payloadLength > encryptConfig.maxChunk) continue;
									if (offset > 0) log(`[SSinbound] detectedLeadingNoise ${offset}B，autoAligned`);
									if (encryptConfig.method !== preferredEncConfig.method) log(`[SSinbound] URL enc=${requestEncryptMethod || preferredEncConfig.method} vs actual ${encryptConfig.method} inconsistent, auto-switched`);
									inboundState.buffer = inboundState.buffer.subarray(initMinLength);
									inboundState.decryptKey = decryptKey;
									inboundState.nonceCounter = nonceCounter;
									inboundState.waitPayloadLength = payloadLength;
									inboundState.encryptConfig = encryptConfig;
									inboundState.hasSalt = true;
									return true;
								} catch (_) { }
							}
						}
						const initFailCheckLength = maxSaltLength + lengthCipherTotalLength + maxAlignScanBytes;
						if (inboundState.buffer.byteLength >= initFailCheckLength) {
							throw new Error(`SS handshake decrypt failed (enc=${requestEncryptMethod || 'auto'}, candidates=${inboundCandidateEncConfig.map(c => c.method).join('/')})`);
						}
						return false;
					};
					const inboundDecryptor = {
						async input(dataChunk) {
							const chunk = dataToUint8Array(dataChunk);
							if (chunk.byteLength > 0) inboundState.buffer = joinBytes(inboundState.buffer, chunk);
							if (!inboundState.hasSalt) {
								const initSuccess = await initInboundDecryptState();
								if (!initSuccess) return [];
							}
							const plaintextChunks = [];
							while (true) {
								if (inboundState.waitPayloadLength === null) {
									const lengthCipherTotalLength = 2 + shadowsocksAeadTagLength;
									if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
									const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
									inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
									const lengthPlain = await decryptShadowsocksAead(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
									if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
									const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
									if (payloadLength < 0 || payloadLength > inboundState.encryptConfig.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
									inboundState.waitPayloadLength = payloadLength;
								}
								const payloadCipherTotalLength = inboundState.waitPayloadLength + shadowsocksAeadTagLength;
								if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
								const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
								inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
								const payloadPlain = await decryptShadowsocksAead(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
								plaintextChunks.push(payloadPlain);
								inboundState.waitPayloadLength = null;
							}
							return plaintextChunks;
						},
					};
					let outboundEncryptor = null;
					const SSmaxBatchBytes = 32 * 1024;
					const getOutboundEncryptor = async () => {
						if (outboundEncryptor) return outboundEncryptor;
						if (!inboundState.encryptConfig) throw new Error('SS cipher is not negotiated');
						const outboundEncConfig = inboundState.encryptConfig;
						const outboundMasterKey = await deriveShadowsocksMasterKey(yourUUID, outboundEncConfig.keyLen);
						const outboundRandomBytes = crypto.getRandomValues(new Uint8Array(outboundEncConfig.saltLen));
						const outboundEncryptKey = await deriveShadowsocksSessionKey(outboundEncConfig, outboundMasterKey, outboundRandomBytes, ['encrypt']);
						const outboundNonceCounter = new Uint8Array(shadowsocksNonceLength);
						let randomBytesSent = false;
						outboundEncryptor = {
							async encryptAndSend(dataChunk, sendChunk) {
								const plaintextData = dataToUint8Array(dataChunk);
								if (!randomBytesSent) {
									await sendChunk(outboundRandomBytes);
									randomBytesSent = true;
								}
								if (plaintextData.byteLength === 0) return;
								let offset = 0;
								while (offset < plaintextData.byteLength) {
									const end = Math.min(offset + outboundEncConfig.maxChunk, plaintextData.byteLength);
									const payloadPlain = plaintextData.subarray(offset, end);
									const lengthPlain = new Uint8Array(2);
									lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
									lengthPlain[1] = payloadPlain.byteLength & 0xff;
									const lengthCipher = await encryptShadowsocksAead(outboundEncryptKey, outboundNonceCounter, lengthPlain);
									const payloadCipher = await encryptShadowsocksAead(outboundEncryptKey, outboundNonceCounter, payloadPlain);
									const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
									frame.set(lengthCipher, 0);
									frame.set(payloadCipher, lengthCipher.byteLength);
									await sendChunk(frame);
									offset = end;
								}
							},
						};
						return outboundEncryptor;
					};
					let SSsendQueue = Promise.resolve();
					const SSenqueueToSend = (chunk) => {
						SSsendQueue = SSsendQueue.then(async () => {
							if (serverSock.readyState !== WebSocket.OPEN) return;
							const initializedOutboundEncryptor = await getOutboundEncryptor();
							await initializedOutboundEncryptor.encryptAndSend(chunk, async (encryptedChunk) => {
								if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
									await WebSocketsendAndWait(serverSock, encryptedChunk.buffer);
								}
							});
						}).catch((error) => {
							log(`[SSsend] encryptionFailed: ${error?.message || error}`);
							closeSocketQuietly(serverSock);
						});
						return SSsendQueue;
					};
					const replySocket = {
						get readyState() {
							return serverSock.readyState;
						},
						send(data) {
							const chunk = dataToUint8Array(data);
							if (chunk.byteLength <= SSmaxBatchBytes) {
								return SSenqueueToSend(chunk);
							}
							for (let i = 0; i < chunk.byteLength; i += SSmaxBatchBytes) {
								SSenqueueToSend(chunk.subarray(i, Math.min(i + SSmaxBatchBytes, chunk.byteLength)));
							}
							return SSsendQueue;
						},
						close() {
							closeSocketQuietly(serverSock);
						}
					};
					sscontext = {
						inboundDecryptor,
						replySocket,
						firstPacketEstablished: false,
						targetHost: '',
						targetPort: 0,
					};
					return sscontext;
				})().finally(() => { ssinitTasks = null });
			}
			return ssinitTasks;
		};

		const handleSSData = async (chunk) => {
			const context = await getSSContext();
			let plaintextChunkArray = null;
			try {
				plaintextChunkArray = await context.inboundDecryptor.input(chunk);
			} catch (err) {
				const msg = err?.message || `${err}`;
				if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
					log(`[SSinbound] decryptionFailed，connectionClosed: ${msg}`);
					closeSocketQuietly(serverSock);
					return;
				}
				throw err;
			}
			for (const plaintextChunk of plaintextChunkArray) {
				let written = false;
				try {
					written = await writeToRemote(plaintextChunk, false);
				} catch (_) {
					written = false;
				}
				if (written) continue;
				if (context.firstPacketEstablished && context.targetHost && context.targetPort > 0) {
					await forwardTcpConnection(context.targetHost, context.targetPort, plaintextChunk, context.replySocket, null, remoteConnWrapper, yourUUID);
					continue;
				}
				const plaintextData = dataToUint8Array(plaintextChunk);
				if (plaintextData.byteLength < 3) throw new Error('invalid ss data');
				const addressType = plaintextData[0];
				let cursor = 1;
				let hostname = '';
				if (addressType === 1) {
					if (plaintextData.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
					hostname = `${plaintextData[cursor]}.${plaintextData[cursor + 1]}.${plaintextData[cursor + 2]}.${plaintextData[cursor + 3]}`;
					cursor += 4;
				} else if (addressType === 3) {
					if (plaintextData.byteLength < cursor + 1) throw new Error('invalid ss domain length');
					const domainLength = plaintextData[cursor];
					cursor += 1;
					if (plaintextData.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
					hostname = shadowsocksTextDecoder.decode(plaintextData.subarray(cursor, cursor + domainLength));
					cursor += domainLength;
				} else if (addressType === 4) {
					if (plaintextData.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
					const ipv6 = [];
					const ipv6View = new DataView(plaintextData.buffer, plaintextData.byteOffset + cursor, 16);
					for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
					hostname = ipv6.join(':');
					cursor += 16;
				} else {
					throw new Error(`invalid ss addressType: ${addressType}`);
				}
				if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
				const port = (plaintextData[cursor] << 8) | plaintextData[cursor + 1];
				cursor += 2;
				const rawClientData = plaintextData.subarray(cursor);
				if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
				context.firstPacketEstablished = true;
				context.targetHost = hostname;
				context.targetPort = port;
				await forwardTcpConnection(hostname, port, rawClientData, context.replySocket, null, remoteConnWrapper, yourUUID);
			}
		};

		readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (isDnsQuery) {
					return forwardUdpPayload(isTrojanProtocol ? 'trojan' : 'vless', chunk, serverSock, null, trojanUDPContext);
				}
				if (detectProtocolType === 'ss') {
					await handleSSData(chunk);
					return;
				}
				if (await writeToRemote(chunk)) return;

				if (detectProtocolType === null) {
					if (url.searchParams.get('enc')) detectProtocolType = 'ss';
					else {
						const bytes = new Uint8Array(chunk);
						detectProtocolType = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
					}
					isTrojanProtocol = detectProtocolType === 'trojan';
					log(`[WSforward] protocolType: ${detectProtocolType} | from: ${url.host} | UA: ${request.headers.get('user-agent') || 'unknown'}`);
				}

				if (detectProtocolType === 'ss') {
					await handleSSData(chunk);
					return;
				}
				if (await writeToRemote(chunk)) return;
				if (detectProtocolType === 'trojan') {
					const parseResult = parseTrojanRequest(chunk, yourUUID);
					if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
					const { port, hostname, rawClientData, isUDP } = parseResult;
					if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
					if (isUDP) {
						isDnsQuery = true;
						if (validDataLength(rawClientData) > 0) return forwardUdpPayload('trojan', rawClientData, serverSock, null, trojanUDPContext);
						return;
					}
					await forwardTcpConnection(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID);
				} else {
					isTrojanProtocol = false;
					const parseResult = parseVLESSRequest(chunk, yourUUID);
					if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
					const { port, hostname, rawIndex, version, isUDP } = parseResult;
					if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
					if (isUDP) {
						if (port === 53) isDnsQuery = true;
						else throw new Error('UDP is not supported');
					}
					const respHeader = new Uint8Array([version[0], 0]);
					const rawData = chunk.slice(rawIndex);
					if (isDnsQuery) {
						return forwardUdpPayload(isTrojanProtocol ? 'trojan' : 'vless', rawData, serverSock, respHeader, trojanUDPContext);
					}
					await forwardTcpConnection(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID);
				}
			},
			close() {
				releaseRemoteWriter();
			},
			abort() {
				releaseRemoteWriter();
			}
		})).catch((err) => {
			const msg = err?.message || `${err}`;
			if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
				log(`[WSforward] connectionEnded: ${msg}`);
			} else {
				log(`[WSforward] processFailed: ${msg}`);
			}
			releaseRemoteWriter();
			closeSocketQuietly(serverSock);
		});

		return new Response(null, { status: 101, webSocket: clientSock });
	}

	async function forwardTrojanUdpPackets(chunk, webSocket, context) {
		const currentChunk = dataToUint8Array(chunk);
		const cacheChunk = context?.cache instanceof Uint8Array ? context.cache : new Uint8Array(0);
		const input = cacheChunk.byteLength ? joinBytes(cacheChunk, currentChunk) : currentChunk;
		let cursor = 0;

		while (cursor < input.byteLength) {
			const packetStart = cursor;
			const atype = input[cursor];
			let addrCursor = cursor + 1;
			let addrLen = 0;
			if (atype === 1) addrLen = 4;
			else if (atype === 4) addrLen = 16;
			else if (atype === 3) {
				if (input.byteLength < addrCursor + 1) break;
				addrLen = 1 + input[addrCursor];
			} else throw new Error(`invalid trojan udp addressType: ${atype}`);

			const portCursor = addrCursor + addrLen;
			if (input.byteLength < portCursor + 6) break;

			const port = (input[portCursor] << 8) | input[portCursor + 1];
			const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
			if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

			const payloadStart = portCursor + 6;
			const payloadEnd = payloadStart + payloadLength;
			if (input.byteLength < payloadEnd) break;

			const addrPortHeader = input.slice(packetStart, portCursor + 2);
			const payload = input.slice(payloadStart, payloadEnd);
			cursor = payloadEnd;

			if (port !== 53) throw new Error('UDP is not supported');
			if (!payload.byteLength) continue;

			let tcpDNSquery = payload;
			if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
				tcpDNSquery = new Uint8Array(payload.byteLength + 2);
				tcpDNSquery[0] = (payload.byteLength >>> 8) & 0xff;
				tcpDNSquery[1] = payload.byteLength & 0xff;
				tcpDNSquery.set(payload, 2);
			}

			const dnsresponseContext = { cache: new Uint8Array(0) };
			await forwardDnsOverTcp(tcpDNSquery, webSocket, null, (dnsRespChunk) => {
				const currentResponseChunk = dataToUint8Array(dnsRespChunk);
				const responseInput = dnsresponseContext.cache.byteLength ? joinBytes(dnsresponseContext.cache, currentResponseChunk) : currentResponseChunk;
				const responseFrameList = [];
				let responseCursor = 0;
				while (responseCursor + 2 <= responseInput.byteLength) {
					const dnsLen = (responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
					const dnsStart = responseCursor + 2;
					const dnsEnd = dnsStart + dnsLen;
					if (dnsEnd > responseInput.byteLength) break;
					const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
					const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
					frame.set(addrPortHeader, 0);
					frame[addrPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
					frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
					frame[addrPortHeader.byteLength + 2] = 0x0d;
					frame[addrPortHeader.byteLength + 3] = 0x0a;
					frame.set(dnsPayload, addrPortHeader.byteLength + 4);
					responseFrameList.push(frame);
					responseCursor = dnsEnd;
				}
				dnsresponseContext.cache = responseInput.slice(responseCursor);
				return responseFrameList.length ? responseFrameList : new Uint8Array(0);
			});
		}

		if (context) context.cache = input.slice(cursor);
	}

	async function forwardUdpPayload(protocol, chunk, webSocket, responseHeader, trojanContext) {
		if (protocol === 'trojan') return forwardTrojanUdpPackets(chunk, webSocket, trojanContext);
		return forwardDnsOverTcp(chunk, webSocket, responseHeader);
	}

	async function forwardTcpConnection(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
		const proxyState = readProxyState();
		log(`[TCPforward] target: ${host}:${portNum} | proxyIP: ${proxyState.proxyIP} | proxyFallback: ${proxyState.enableProxyFallback ? 'is' : 'no'} | proxyType: ${proxyState.enableSOCKS5Proxy || 'proxyip'} | global: ${proxyState.enableSOCKS5GlobalProxy ? 'is' : 'no'}`);
		const connectTimeoutMs = 1000;
		let sentFirstPacketViaProxy = false;

		async function waitConnectionEstablish(remoteSock, timeoutMs = connectTimeoutMs) {
			await Promise.race([
				remoteSock.opened,
				new Promise((_, reject) => setTimeout(() => reject(new Error('connectTimeout')), timeoutMs))
			]);
		}

		async function connectDirect(address, port, data = null, allProxyArray = null, proxyFallback = true) {
			let remoteSock;
			if (allProxyArray && allProxyArray.length > 0) {
				const baseProxyArrayIndex = readProxyState().cachedProxyArrayIndex;
				for (let i = 0; i < allProxyArray.length; i++) {
					const proxyArrayIndex = (baseProxyArrayIndex + i) % allProxyArray.length;
					const [proxyAddr, proxyPort] = allProxyArray[proxyArrayIndex];
					try {
						log(`[proxyConnect] tryConnectTo: ${proxyAddr}:${proxyPort} (index: ${proxyArrayIndex})`);
						remoteSock = connect({ hostname: proxyAddr, port: proxyPort });
						await waitConnectionEstablish(remoteSock);
						if (validDataLength(data) > 0) {
							const testWriter = remoteSock.writable.getWriter();
							await testWriter.write(data);
							testWriter.releaseLock();
						}
						log(`[proxyConnect] connectedTo: ${proxyAddr}:${proxyPort}`);
						updateCachedProxyArrayIndex(proxyArrayIndex);
						return remoteSock;
					} catch (err) {
						log(`[proxyConnect] connectionFailed: ${proxyAddr}:${proxyPort}, error: ${err.message}`);
						safeClose(remoteSock)
						continue;
					}
				}
			}

			if (proxyFallback) {
				remoteSock = connect({ hostname: address, port: port });
				await waitConnectionEstablish(remoteSock);
				if (validDataLength(data) > 0) {
					const writer = remoteSock.writable.getWriter();
					await writer.write(data);
					writer.releaseLock();
				}
				return remoteSock;
			} else {
				closeSocketQuietly(ws);
				throw new Error('[proxyConnect] allProxyConnFailed，proxyFallbackNotEnabled，connectionTerminated');
			}
		}

		async function connectViaProxy(allowSendFirstPacket = true) {
			if (remoteConnWrapper.connectingPromise) {
				await remoteConnWrapper.connectingPromise;
				return;
			}

			const sendFirstPacketNow = allowSendFirstPacket && !sentFirstPacketViaProxy && validDataLength(rawData) > 0;
			const currentFirstPacketData = sendFirstPacketNow ? rawData : null;

			const currentConnTask = (async () => {
				let newSocket;
				const currentProxyState = readProxyState();
				if (currentProxyState.enableSOCKS5Proxy === 'socks5') {
					log(`[SOCKS5proxy] proxyTo: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, currentFirstPacketData);
				} else if (currentProxyState.enableSOCKS5Proxy === 'http') {
					log(`[HTTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, currentFirstPacketData);
				} else if (currentProxyState.enableSOCKS5Proxy === 'https') {
					log(`[HTTPSproxy] proxyTo: ${host}:${portNum}`);
					newSocket = isIPHostname(currentProxyState.parsedSocks5Address.hostname)
						? await httpsConnect(host, portNum, currentFirstPacketData)
						: await httpConnect(host, portNum, currentFirstPacketData, true);
				} else if (currentProxyState.enableSOCKS5Proxy === 'turn') {
					log(`[TURNproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await turnConnect(currentProxyState.parsedSocks5Address, host, portNum);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(dataToUint8Array(currentFirstPacketData)) }
						finally { safeRelease(writer) }
					}
				} else if (currentProxyState.enableSOCKS5Proxy === 'sstp') {
					log(`[SSTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await sstpConnect(currentProxyState.parsedSocks5Address, host, portNum);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(dataToUint8Array(currentFirstPacketData)) }
						finally { safeRelease(writer) }
					}
				} else {
					if (!currentProxyState.proxyIP) {
						closeSocketQuietly(ws);
						throw new Error('[proxyConnect] proxyIPNotConfigured，retryConnectionTerminated');
					}
					log(`[proxyConnect] proxyTo: ${host}:${portNum}`);
					const allProxyArray = await resolveProxyAddresses(currentProxyState.proxyIP, host, yourUUID);
					newSocket = await connectDirect('proxyip.tp1.090227.xyz', 1, currentFirstPacketData, allProxyArray, currentProxyState.enableProxyFallback);
				}
				if (sendFirstPacketNow) sentFirstPacketViaProxy = true;
				remoteConnWrapper.socket = newSocket;
				newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
				connectStreams(newSocket, ws, respHeader, null);
			})();

			remoteConnWrapper.connectingPromise = currentConnTask;
			try {
				await currentConnTask;
			} finally {
				if (remoteConnWrapper.connectingPromise === currentConnTask) {
					remoteConnWrapper.connectingPromise = null;
				}
			}
		}
		remoteConnWrapper.retryConnect = async () => connectViaProxy(!sentFirstPacketViaProxy);

		const currentProxyState = readProxyState();
		if (currentProxyState.enableSOCKS5Proxy && (currentProxyState.enableSOCKS5GlobalProxy || currentProxyState.SOCKS5whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
			log(`[TCPforward] enabled SOCKS5/HTTP/HTTPS/TURN/SSTP globalProxy`);
			try {
				await connectViaProxy();
			} catch (err) {
				log(`[TCPforward] SOCKS5/HTTP/HTTPS/TURN/SSTP proxyConnFailed: ${err.message}`);
				throw err;
			}
		} else {
			try {
				log(`[TCPforward] tryDirectConnectTo: ${host}:${portNum}`);
				const initialSocket = await connectDirect(host, portNum, rawData);
				remoteConnWrapper.socket = initialSocket;
				connectStreams(initialSocket, ws, respHeader, async () => {
					if (remoteConnWrapper.socket !== initialSocket) return;
					await connectViaProxy();
				});
			} catch (err) {
				log(`[TCPforward] directConnect ${host}:${portNum} failed: ${err.message}`);
				await connectViaProxy();
			}
		}
	}

	async function forwardDnsOverTcp(udpChunk, webSocket, respHeader, responseWrapper = null) {
		const requestData = dataToUint8Array(udpChunk);
		const requestByteCount = requestData.byteLength;
		log(`[UDPforward] received DNS request: ${requestByteCount}B -> 8.8.4.4:53`);
		try {
			const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
			let vlessHeader = respHeader;
			const writer = tcpSocket.writable.getWriter();
			await writer.write(requestData);
			log(`[UDPforward] DNS requestWrittenToUpstream: ${requestByteCount}B`);
			writer.releaseLock();
			await tcpSocket.readable.pipeTo(new WritableStream({
				async write(chunk) {
					const originalResponse = dataToUint8Array(chunk);
					log(`[UDPforward] received DNS response: ${originalResponse.byteLength}B`);
					const wrapResult = responseWrapper ? await responseWrapper(originalResponse) : originalResponse;
					const sendFragmentList = Array.isArray(wrapResult) ? wrapResult : [wrapResult];
					if (!sendFragmentList.length) return;
					if (webSocket.readyState === WebSocket.OPEN) {
						for (const fragment of sendFragmentList) {
							const forwardResponse = dataToUint8Array(fragment);
							if (!forwardResponse.byteLength) continue;
							if (vlessHeader) {
								const response = new Uint8Array(vlessHeader.length + forwardResponse.byteLength);
								response.set(vlessHeader, 0);
								response.set(forwardResponse, vlessHeader.length);
								await WebSocketsendAndWait(webSocket, response.buffer);
								vlessHeader = null;
							} else {
								await WebSocketsendAndWait(webSocket, forwardResponse);
							}
						}
					}
				},
			}));
		} catch (error) {
			log(`[UDPforward] DNS forwardFailed: ${error?.message || error}`);
		}
	}

	return {
		handleXHTTP: handleXHTTPTransport,
		handleGRPC: handleGRPCTransport,
		handleWebSocket: handleWebSocketTransport,
	};
}
