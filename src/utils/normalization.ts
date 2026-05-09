export async function normalizeToArray(content) {
	let replacedContent = String(content || '').replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (replacedContent.charAt(0) === ',') replacedContent = replacedContent.slice(1);
	if (replacedContent.charAt(replacedContent.length - 1) === ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);
	return replacedContent ? replacedContent.split(',') : [];
}
