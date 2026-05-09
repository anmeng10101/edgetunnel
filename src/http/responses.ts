export const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };
export const TEXT_HEADERS = { 'Content-Type': 'text/plain;charset=utf-8' };
export const HTML_HEADERS = {
	'Content-Type': 'text/html;charset=utf-8',
	'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
	'Pragma': 'no-cache',
	'Expires': '0',
};

export function jsonResponse(data: unknown, status = 200, headers: HeadersInit = JSON_HEADERS) {
	return new Response(JSON.stringify(data, null, 2), { status, headers });
}

export function htmlResponse(body: string, status = 200) {
	return new Response(body, { status, headers: HTML_HEADERS });
}

export function redirectResponse(location: string, status = 302) {
	return new Response('redirecting...', { status, headers: { Location: location } });
}
