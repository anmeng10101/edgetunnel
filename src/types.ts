export type LogFn = (...args: unknown[]) => void;
export type Bytes = Uint8Array<ArrayBufferLike>;
export type ByteSource = Bytes | ArrayBuffer | ArrayBufferView<ArrayBufferLike> | ArrayLike<number> | null | undefined;

export type ProxyProtocol = 'socks5' | 'http' | 'https' | 'turn' | 'sstp' | null;

export interface ParsedProxyAddress {
	username?: string;
	password?: string;
	hostname?: string;
	port?: number;
}

export interface SocketLike {
	readable: ReadableStream;
	writable: WritableStream;
	opened?: Promise<unknown>;
	closed?: Promise<unknown>;
	close?: () => void;
}

export interface WebSocketBridge {
	readyState: number;
	send(data: unknown): void | Promise<void>;
	close(): void;
}

export type ConnectFn = (address: string | { hostname: string; port: number }) => SocketLike;

export interface ProxyState {
	mySOCKS5Account?: string | null;
	proxyIP?: string;
	enableProxyFallback?: boolean;
	enableSOCKS5GlobalProxy?: boolean;
	enableSOCKS5Proxy?: ProxyProtocol;
	parsedSocks5Address?: ParsedProxyAddress;
	SOCKS5whitelist?: readonly string[];
	cachedProxyArrayIndex?: number;
}

export interface DoHAnswer {
	name?: string;
	type: number;
	TTL?: number;
	data: string;
	rdata?: Uint8Array;
}

export type ProxyAddressEntry = [host: string, port: number];

export type ProxyConnector = (targetHost: string, targetPort: number, initialData?: ByteSource) => Promise<SocketLike>;
export type TunneledProxyConnector = (proxy: ParsedProxyAddress, targetHost: string, targetPort: number) => Promise<SocketLike>;

export interface ParsedProtocolRequest {
	hasError: boolean;
	message?: string;
	addressType?: number;
	port?: number;
	hostname?: string;
	isUDP?: boolean;
	rawIndex?: number;
	rawClientData?: Uint8Array;
	version?: Uint8Array;
}

export interface XHTTPFirstPacket {
	protocol: 'trojan' | 'vless';
	hostname: string;
	port: number;
	isUDP: boolean;
	rawData: Uint8Array;
	respHeader: Uint8Array | null;
	reader: ReadableStreamDefaultReader;
}

export interface ShadowsocksCipherConfig {
	method: string;
	keyLen: number;
	saltLen: number;
	maxChunk: number;
	aesLength: number;
}

export interface RuntimeConfig {
	UUID?: string;
	HOSTS?: string[];
	Fingerprint?: string;
	transportProtocol?: string;
	gRPCmode?: string;
	gRPCUserAgent?: string;
	randomPath?: boolean;
}
