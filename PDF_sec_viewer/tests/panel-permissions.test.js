'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const express = require('express'), session = require('express-session'), bcrypt = require('bcryptjs');
const previous = process.cwd(), oldUpload = process.env.UPLOAD_DIR;
const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-permissions-')); fs.mkdirSync(path.join(folder, 'data'));
process.chdir(folder); process.env.UPLOAD_DIR = folder;
const originalHash = bcrypt.hashSync('Owner.Test.Password123', 4);
const legacy = new (require('better-sqlite3'))(path.join(folder, 'data/database.sqlite'));
legacy.exec(`CREATE TABLE admin_users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT(datetime('now')))`);
legacy.prepare('INSERT INTO admin_users(username,password_hash) VALUES (?,?)').run('Owner', originalHash); legacy.close();
const db = require('../src/config/database');
let server, base, docId, linkId, sectorId;
const cookies = {};
const snapshot = () => Object.fromEntries(['documents', 'access_links', 'access_logs', 'image_preparations', 'document_revisions'].map(table => [table, db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()]));
async function request(route, { role = 'owner', method = 'GET', values, cookie, body, headers = {} } = {}) {
    const response = await fetch(base + route, { method, redirect: 'manual',
        headers: { cookie: cookie ?? cookies[role] ?? '', ...(values ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...headers },
        body: values ? new URLSearchParams(values) : body });
    if (response.headers.get('set-cookie')) cookies[role] = response.headers.get('set-cookie').split(';')[0];
    const text = await response.text(); return { status: response.status, location: response.headers.get('location'), text };
}
const login = (username, password, role) => request('/admin/login', { role, method: 'POST', values: { username, password } });
async function csrf(route, role = 'owner') {
    const response = await request(route, { role }); assert.equal(response.status, 200);
    const token = response.text.match(/name="_csrf" value="([a-f0-9]{64})"/)?.[1]; assert.ok(token); return token;
}
before(async () => {
    docId = require('../src/services/documentService').createDocument('Private collection', 'original.pdf', 'original.pdf', 100, 228);
    fs.writeFileSync(path.join(folder, 'original.pdf'), '%PDF-private');
    linkId = require('../src/services/accessService').createLink(docId, 'unchanged-customer-token', '<script>Customer</script>', 'client@example.com', 'never-expose-customer-hash', 10, '2099-12-31');
    const app = express(); app.use(express.urlencoded({ extended: false })); app.use(express.json());
    app.use(session({ secret: 'test-only-session-secret', resave: false, saveUninitialized: false }));
    app.set('view engine', 'ejs'); app.set('views', path.resolve(__dirname, '../views'));
    app.get('/forge-role', (req, res) => {
        const user = db.prepare('SELECT * FROM admin_users WHERE id=?').get(sectorId);
        req.session.adminId = sectorId; req.session.panelAuthVersion = user.auth_version;
        req.session.role = 'admin'; req.session.adminRole = 'admin'; res.end('ok');
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

test('migration preserves the existing administrator identity and grants its original management permissions', async () => {
    const owner = db.prepare('SELECT * FROM admin_users WHERE id=1').get();
    assert.equal(owner.username, 'Owner'); assert.equal(owner.password_hash, originalHash);
    assert.equal(owner.role, 'admin'); assert.equal(owner.is_active, 1); assert.equal(owner.must_change_password, 0);
    const response = await login('Owner', 'Owner.Test.Password123', 'owner');
    assert.equal(response.status, 302); assert.equal(response.location, '/admin/dashboard');
    const dashboard = await request('/admin/dashboard'); assert.equal(dashboard.status, 200); assert.match(dashboard.text, /\/admin\/users/);
});

test('only an authenticated administrator with a valid CSRF token can create a sector account', async () => {
    const anonymous = await request('/admin/users', { role: 'anonymous' }); assert.equal(anonymous.location, '/admin/login');
    const missing = await request('/admin/users', { method: 'POST', values: { username: 'Barbara', password: 'Test01' } }); assert.equal(missing.status, 403);
    const token = await csrf('/admin/users');
    const unicode = await request('/admin/users', { method: 'POST', values: { username: 'Barbara', password: 'Test01', _csrf: 'á'.repeat(64) } }); assert.equal(unicode.status, 403);
    for (const values of [{ username: 'Barbara', password: 'Test01', role: 'admin' }, { username: 'Barbara', password: 'short' }]) {
        const response = await request('/admin/users', { method: 'POST', values: { ...values, _csrf: token } }); assert.equal(response.status, 400);
    }
    const response = await request('/admin/users', { method: 'POST', values: { username: 'Barbara', password: 'Test01', _csrf: token } });
    assert.equal(response.status, 302); assert.equal(response.location, '/admin/users');
    const user = db.prepare("SELECT * FROM admin_users WHERE username='Barbara'").get(); sectorId = user.id;
    assert.equal(user.role, 'setor_atacado'); assert.equal(user.must_change_password, 1); assert.notEqual(user.password_hash, 'Test01');
    assert.ok(await bcrypt.compare('Test01', user.password_hash));
    const duplicate = await request('/admin/users', { method: 'POST', values: { username: 'bARbara', password: 'Test01', _csrf: token } }); assert.equal(duplicate.status, 400);
});

test('first login requires the initial password to be replaced before any consultation or management request', async () => {
    const before = snapshot(); const result = await login('barbara', 'Test01', 'sector');
    assert.equal(result.status, 302); assert.equal(result.location, '/admin/account/password');
    for (const [route, method] of [['/admin/accesses', 'GET'], ['/admin/users', 'POST'], [`/admin/documents/${docId}/delete`, 'POST']]) {
        const response = await request(route, { role: 'sector', method }); assert.equal(response.location, '/admin/account/password');
    }
    assert.deepEqual(snapshot(), before);
    const token = await csrf('/admin/account/password', 'sector');
    for (const values of [
        { current_password: 'wrong', password: 'Atacado.Test.New123', confirm_password: 'Atacado.Test.New123' },
        { current_password: 'Test01', password: 'short', confirm_password: 'short' },
        { current_password: 'Test01', password: 'Atacado.Test.New123', confirm_password: 'does-not-match' }
    ]) {
        const response = await request('/admin/account/password', { role: 'sector', method: 'POST', values: { ...values, _csrf: token } }); assert.equal(response.status, 400);
    }
    const priorCookie = cookies.sector;
    const changed = await request('/admin/account/password', { role: 'sector', method: 'POST', values: { current_password: 'Test01', password: 'Atacado.Test.New123', confirm_password: 'Atacado.Test.New123', _csrf: token } });
    assert.equal(changed.location, '/admin/accesses'); assert.notEqual(cookies.sector, priorCookie);
    assert.equal(db.prepare('SELECT must_change_password FROM admin_users WHERE id=?').get(sectorId).must_change_password, 0);
    assert.equal((await request('/admin/accesses', { cookie: priorCookie, role: 'stale' })).location, '/admin/login');
    assert.deepEqual(snapshot(), before);
});

test('sector consultation contains existing access details, escapes customer text and does not expose secrets or management controls', async () => {
    const before = snapshot(); const response = await request('/admin/accesses', { role: 'sector' });
    assert.equal(response.status, 200); assert.match(response.text, /2027_A001/); assert.match(response.text, /unchanged-customer-token/);
    assert.match(response.text, /&lt;script&gt;Customer&lt;\/script&gt;/);
    for (const forbidden of ['never-expose-customer-hash', 'Test01', 'Criar usuário', 'Editar limites', 'Excluir', '/preview', '/admin/users', '/admin/logs']) assert.ok(!response.text.includes(forbidden), forbidden);
    assert.equal((await request('/admin/dashboard', { role: 'sector' })).location, '/admin/accesses');
    assert.deepEqual(snapshot(), before);
});

test('sector requests are rejected server-side for every management operation, including uploads, PDF previews and forged roles', async () => {
    const before = snapshot(), files = fs.readdirSync(folder);
    const gets = ['/admin/users', '/admin/logs', `/admin/documents/${docId}`, `/admin/documents/${docId}/images/status`, `/admin/documents/${docId}/revisions/status`,
        `/admin/links/${linkId}/preview`, `/admin/links/${linkId}/preview/info`, `/admin/links/${linkId}/preview/pdf/info`, `/admin/links/${linkId}/preview/pdf/document`,
        `/admin/links/${linkId}/preview/pdf/parts/version/0`, `/admin/links/${linkId}/preview/images/${'0'.repeat(64)}/1/view`, `/admin/links/${linkId}/preview/revisions/1/pdf/document`];
    for (const route of gets) assert.equal((await request(route, { role: 'sector' })).status, 403, route);
    const posts = ['/admin/documents/upload', `/admin/documents/${docId}/revisions`, ...['toggle','delete','links','images/prepare'].map(action => `/admin/documents/${docId}/${action}`),
        ...['restore','retry','cancel'].map(action => `/admin/documents/${docId}/revisions/1/${action}`), ...['limits','toggle','delete','images/prepare'].map(action => `/admin/links/${linkId}/${action}`),
        '/admin/users', '/admin/users/1/toggle', '/admin/users/1/reset-password'];
    for (const route of posts) assert.equal((await request(route, { role: 'sector', method: 'POST', values: { role: 'admin', max_views: '999', password: 'escalation-attempt' } })).status, 403, route);
    const form = new FormData(); form.append('pdf', new Blob(['%PDF-forbidden'], { type: 'application/pdf' }), 'forbidden.pdf');
    assert.equal((await request('/admin/documents/upload', { role: 'sector', method: 'POST', body: form })).status, 403);
    for (const method of ['PUT','PATCH','DELETE']) assert.equal((await request(`/admin/links/${linkId}`, { role: 'sector', method })).status, 403);
    await request('/forge-role', { role: 'forged' });
    assert.equal((await request(`/admin/documents/${docId}`, { role: 'forged' })).status, 403);
    assert.deepEqual(snapshot(), before); assert.deepEqual(fs.readdirSync(folder), files);
});

test('deactivation and reactivation invalidate previously issued sessions immediately', async () => {
    const token = await csrf('/admin/users');
    assert.equal((await request(`/admin/users/${sectorId}/toggle`, { method: 'POST', values: { _csrf: token } })).status, 302);
    assert.equal((await request('/admin/accesses', { role: 'sector' })).location, '/admin/login');
    assert.equal((await login('Barbara', 'Atacado.Test.New123', 'disabled')).status, 401);
    await request(`/admin/users/${sectorId}/toggle`, { method: 'POST', values: { _csrf: token } });
    assert.equal((await login('Barbara', 'Atacado.Test.New123', 'sector')).location, '/admin/accesses');
});

test('a password reset revokes every open sector session and requires another first-login change', async () => {
    await login('Barbara', 'Atacado.Test.New123', 'second');
    const token = await csrf('/admin/users');
    const reset = await request(`/admin/users/${sectorId}/reset-password`, { method: 'POST', values: { password: 'Reset01', _csrf: token } });
    assert.equal(reset.status, 302);
    for (const role of ['sector','second']) assert.equal((await request('/admin/accesses', { role })).location, '/admin/login');
    assert.equal((await login('Barbara', 'Atacado.Test.New123', 'old-password')).status, 401);
    assert.equal((await login('Barbara', 'Reset01', 'sector')).location, '/admin/account/password');
    assert.equal(db.prepare('SELECT password_hash FROM admin_users WHERE id=1').get().password_hash, originalHash);
});

test('management cannot deactivate or reset an existing administrator through sector-only controls', async () => {
    const before = db.prepare('SELECT * FROM admin_users WHERE id=1').get(), token = await csrf('/admin/users');
    for (const action of ['toggle','reset-password']) {
        const response = await request('/admin/users/1/' + action, { method: 'POST', values: { password: 'Reset01', _csrf: token } }); assert.equal(response.status, 400);
    }
    assert.deepEqual(db.prepare('SELECT * FROM admin_users WHERE id=1').get(), before);
});

test('deleting an account cannot leave a reusable privileged session behind', async () => {
    const id = db.prepare("INSERT INTO admin_users(username,password_hash) VALUES ('Disposable',?)").run(originalHash).lastInsertRowid;
    assert.equal((await login('Disposable', 'Owner.Test.Password123', 'deleted')).location, '/admin/dashboard');
    db.prepare('DELETE FROM admin_users WHERE id=?').run(id);
    assert.equal((await request('/admin/users', { role: 'deleted' })).location, '/admin/login');
    assert.equal((await request('/admin/users')).status, 200);
});

test('failed logins are rate limited without changing documents or access identities', async () => {
    const before = snapshot(); let response;
    for (let i = 0; i < 12; i++) { response = await login('Barbara', 'wrong-password', 'guess'); if (response.status === 429) break; }
    assert.equal(response.status, 429); assert.deepEqual(snapshot(), before);
});
