'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), os = require('os'), express = require('express');
const previous = process.cwd(), oldUpload = process.env.UPLOAD_DIR;
const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'access-search-')); fs.mkdirSync(path.join(folder, 'data'));
process.chdir(folder); process.env.UPLOAD_DIR = folder;
const db = require('../src/config/database');
db.prepare("INSERT INTO admin_users(id,username,password_hash,role) VALUES (1,'Owner','unused','admin'),(2,'Wholesale','unused','setor_atacado')").run();
const { createDocument } = require('../src/services/documentService');
const { createLink } = require('../src/services/accessService');
let server, base, collection, otherCollection, joao, maria, other;
const snapshot = () => Object.fromEntries(['access_links','access_logs','documents','document_revisions','image_preparations'].map(table => [table, db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()]));
async function search(query = '', { role = 'sector', documentId } = {}) {
    const url = documentId ? `/admin/documents/${documentId}` : '/admin/accesses';
    const response = await fetch(base + url + '?' + new URLSearchParams({ q: query }), { redirect: 'manual', headers: { 'x-actor': role } });
    return { status: response.status, text: await response.text(), location: response.headers.get('location') };
}
function tokens(html) { return [...html.matchAll(/data-url="[^"<>]*\/v\/([^"<>]+)"/g)].map(match => match[1]); }
before(async () => {
    collection = createDocument('Coleção Verão', 'one.pdf', 'one.pdf', 100, 2);
    otherCollection = createDocument('Inverno Especial', 'two.pdf', 'two.pdf', 100, 2);
    joao = createLink(collection, 'customer-joao-token', 'João da Silva', 'joao@loja.example', 'SECRET-CUSTOMER-HASH', 10, null);
    maria = createLink(collection, 'customer-maria-token', 'Maria Souza', 'maria@boutique.example', 'ANOTHER-SECRET-HASH', 10, null);
    other = createLink(otherCollection, 'customer-other-token', 'João Ferreira', 'other@outlet.example', 'OTHER-PRIVATE-HASH', 10, null);
    db.prepare('UPDATE access_links SET access_code=? WHERE id=?').run('58391', joao);
    const app = express(); app.use(express.urlencoded({ extended: false })); app.use(express.json());
    app.set('view engine', 'ejs'); app.set('views', path.resolve(__dirname, '../views'));
    app.use((req, res, next) => {
        const actor = req.get('x-actor'); req.session = actor === 'owner' ? { adminId: 1, panelAuthVersion: 0 } : actor === 'sector' ? { adminId: 2, panelAuthVersion: 0 } : {}; next();
    });
    app.use('/admin', require('../src/routes/admin'));
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
    if (server) await new Promise(resolve => server.close(resolve)); db.close(); process.chdir(previous);
    if (oldUpload === undefined) delete process.env.UPLOAD_DIR; else process.env.UPLOAD_DIR = oldUpload;
    fs.rmSync(folder, { recursive: true, force: true });
});

test('name search accepts partial text, multiple terms, uppercase and missing accents for both roles', async () => {
    for (const role of ['owner','sector']) {
        for (const [query, expected] of [['JOAO', ['customer-other-token','customer-joao-token']], ['jOãO sil', ['customer-joao-token']], ['sou', ['customer-maria-token']], ['silva loja', ['customer-joao-token']]]) {
            const response = await search(query, { role }); assert.equal(response.status, 200); assert.deepEqual(tokens(response.text).sort(), expected.sort());
        }
    }
});

test('email, full and partial codes, legacy identifiers and lookbook names are searchable', async () => {
    const version = db.prepare('SELECT version_code FROM access_links WHERE id=?').get(joao).version_code;
    for (const query of ['JOAO@LOJA', version, '2027_' + version, 'Versão:2027_' + version, '58391']) {
        const response = await search(query); assert.deepEqual(tokens(response.text), ['customer-joao-token'], query);
    }
    assert.deepEqual(tokens((await search('colecao verao')).text).sort(), ['customer-joao-token','customer-maria-token']);
    assert.deepEqual(tokens((await search('inverno')).text), ['customer-other-token']);
});

test('copied URLs and tokens are matched as text without fetching any address', async () => {
    for (const query of ['customer-joao', '/v/customer-joao-token', 'https://lookbook.charth.cloud/v/customer-joao-token', 'http://127.0.0.1:1/v/customer-joao-token?anything=yes#page']) {
        assert.deepEqual(tokens((await search(query)).text), ['customer-joao-token']);
    }
});

test('empty and missing results expose clear counts and allow clearing the query', async () => {
    const all = await search('   '); assert.equal(tokens(all.text).length, 3); assert.match(all.text, /3 de 3 acessos/);
    const none = await search('no-such-recipient'); assert.deepEqual(tokens(none.text), []);
    assert.match(none.text, /Nenhum acesso encontrado/); assert.match(none.text, /0 de 3 acessos/); assert.match(none.text, /Limpar busca/);
    assert.match((await search('maria')).text, /1 de 3 acessos/);
});

test('document search filters only its access table while management and other document context stay available', async () => {
    const found = await search('JOAO', { role: 'owner', documentId: collection });
    assert.equal(found.status, 200); assert.deepEqual(tokens(found.text), ['customer-joao-token']);
    assert.match(found.text, /1 de 2 acessos/); assert.match(found.text, /Criar Novo Acesso/); assert.match(found.text, /Atualizar PDF/);
    const scoped = await search('outlet', { role: 'owner', documentId: collection }); assert.deepEqual(tokens(scoped.text), []);
    assert.match(scoped.text, new RegExp(`/admin/documents/${collection}#access-links`));
    assert.equal((await search('JOAO', { role: 'sector', documentId: collection })).status, 403);
});

test('search cannot inspect password hashes, inject HTML/SQL, mutate access state or bypass authentication', async () => {
    const before = snapshot();
    for (const query of ['SECRET-CUSTOMER-HASH', "' OR 1=1 --", '<img src=x onerror=alert(1)>']) {
        const response = await search(query); assert.equal(response.status, 200); assert.deepEqual(tokens(response.text), []);
        assert.ok(!response.text.includes('<img src=x onerror='));
    }
    const invalid = await fetch(base + '/admin/accesses?q[]=joao', { headers: { 'x-actor': 'sector' } }); assert.equal(invalid.status, 200); await invalid.text();
    const denied = await search('joao', { role: 'anonymous' }); assert.equal(denied.location, '/admin/login');
    const readonly = await search('joao');
    for (const forbidden of ['Editar limites', 'Excluir', '/admin/users', '/preview']) assert.ok(!readonly.text.includes(forbidden));
    assert.deepEqual(snapshot(), before);
});
