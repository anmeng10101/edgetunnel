import adminTemplate from './templates/admin.html';
import loginTemplate from './templates/login.html';
import { htmlResponse } from '../http/responses.js';

function statusPage(title: string, message: string, status = 404) {
	return htmlResponse(`<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<meta name="robots" content="noindex,nofollow">
	<title>${title}</title>
	<style>
		*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#020617,#111827);color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
		.card{width:min(520px,calc(100vw - 32px));padding:30px;border-radius:24px;background:rgba(15,23,42,.82);border:1px solid rgba(148,163,184,.22);box-shadow:0 24px 70px rgba(0,0,0,.38);backdrop-filter:blur(16px)}
		h1{margin:0 0 14px;font-size:26px}p{margin:0;color:#cbd5e1;line-height:1.7}
	</style>
</head>
<body><section class="card"><h1>${title}</h1><p>${message}</p></section></body>
</html>`, status);
}

export function renderMissingAdminPage() {
	return statusPage('缺少 ADMIN 环境变量', '请在 Cloudflare Pages 的环境变量中设置 ADMIN，然后重新部署。');
}

export function renderMissingKvPage() {
	return statusPage('缺少 KV 绑定或 UUID', '请绑定名为 KV 的 KV Namespace，或者设置有效的 UUID 环境变量后重新部署。');
}

export function renderLoginPage() {
	return htmlResponse(loginTemplate);
}

export function renderAdminPage() {
	return htmlResponse(adminTemplate);
}
