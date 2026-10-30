'use strict';
function searchTerm(value) {
    return typeof value === 'string' ? value.trim().slice(0, 200) : '';
}
function normalized(value) {
    return String(value || '').normalize('NFD').replace(/\p{M}/gu, '').toLocaleLowerCase('pt-BR');
}
function filterAccesses(links, query, documentTitle = '') {
    const term = searchTerm(query);
    // Accept a copied customer URL as well as its token; never fetch the URL.
    const token = term.match(/^(?:https?:\/\/[^/\s]+)?\/v\/([a-z0-9_-]+)\/?(?:[?#].*)?$/i)?.[1];
    const words = normalized(token || term).split(/\s+/).filter(Boolean);
    if (!words.length) return links;
    return links.filter(link => {
        const text = normalized([link.recipient_name, link.recipient_email, link.version_code,
            link.version_code && 'Versão:2027_' + link.version_code, link.access_code, link.token,
            link.document_title || documentTitle].filter(Boolean).join(' '));
        return words.every(word => text.includes(word));
    });
}
module.exports = { searchTerm, filterAccesses };
