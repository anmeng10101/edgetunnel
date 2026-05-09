export function getAuthCookie(request) {
	const cookies = request.headers.get('Cookie') || '';
	const match = cookies.split(';').find(c => c.trim().startsWith('auth='));
	if (!match) return null;
	return match.substring(match.indexOf('=') + 1);
}
