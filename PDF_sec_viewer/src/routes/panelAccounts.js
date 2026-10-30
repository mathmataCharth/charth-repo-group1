'use strict';
const router = require('express').Router();
const db = require('../config/database');
const adminAuth = require('../middleware/adminAuth');
const panelAuth = require('../middleware/panelAuth');
const service = require('../services/panelUserService');
const { comparePassword, hashPassword } = require('../utils/hash');
const { searchTerm, filterAccesses } = require('../utils/accessSearch');
function users(res, error = null, status = 200) {
    const users = db.prepare('SELECT id,username,role,is_active,must_change_password,created_at FROM admin_users ORDER BY id').all();
    return res.status(status).render('admin/users', { users, error });
}
router.get('/users', adminAuth, (req, res) => users(res));
router.post('/users', adminAuth, panelAuth.csrf, async (req, res) => {
    try {
        if (req.body.role && req.body.role !== 'setor_atacado') throw Object.assign(new Error('Somente o perfil setor atacado pode ser criado.'), { status: 400 });
        await service.createSectorUser(req.body.username, req.body.password);
        res.redirect('/admin/users');
    } catch (error) { users(res, error.status ? error.message : 'Não foi possível criar o usuário.', error.status || 503); }
});
router.post('/users/:id/reset-password', adminAuth, panelAuth.csrf, async (req, res) => {
    try { await service.resetSectorPassword(req.params.id, req.body.password); res.redirect('/admin/users'); }
    catch (error) { users(res, error.status ? error.message : 'Não foi possível redefinir a senha.', error.status || 503); }
});
router.post('/users/:id/toggle', adminAuth, panelAuth.csrf, (req, res) => {
    try { service.toggleSectorUser(req.params.id); res.redirect('/admin/users'); }
    catch (error) { users(res, error.message, error.status || 503); }
});
router.get('/account/password', panelAuth, (req, res) => res.render('admin/change-password', { error: null }));
router.post('/account/password', panelAuth, panelAuth.csrf, async (req, res) => {
    try {
        const user = db.prepare('SELECT * FROM admin_users WHERE id=?').get(req.panelUser.id);
        if (typeof req.body.current_password !== 'string' || !await comparePassword(req.body.current_password, user.password_hash)) throw Object.assign(new Error('A senha atual está incorreta.'), { status: 400 });
        const next = service.password(req.body.password, 12);
        if (next !== req.body.confirm_password) throw Object.assign(new Error('A confirmação da senha não confere.'), { status: 400 });
        if (await comparePassword(next, user.password_hash)) throw Object.assign(new Error('Escolha uma senha diferente da inicial.'), { status: 400 });
        const hash = await hashPassword(next);
        const updated = db.prepare(`UPDATE admin_users SET password_hash=?,must_change_password=0,auth_version=auth_version+1
            WHERE id=? AND password_hash=? AND auth_version=? AND is_active=1 RETURNING auth_version`).get(hash, user.id, user.password_hash, user.auth_version);
        if (!updated) return res.status(409).send('Sua conta mudou. Entre novamente para continuar.');
        await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
        req.session.adminId = user.id; req.session.adminUsername = user.username; req.session.panelAuthVersion = updated.auth_version;
        res.redirect(user.role === 'admin' ? '/admin/dashboard' : '/admin/accesses');
    } catch (error) { res.status(error.status || 503).render('admin/change-password', { error: error.status ? error.message : 'Não foi possível atualizar a senha.' }); }
});
router.get('/accesses', panelAuth, (req, res) => {
    const links = db.prepare(`SELECT al.id,al.token,al.recipient_name,al.recipient_email,al.version_code,al.access_code,al.max_views,al.views_count,
        al.expires_at,al.is_active,al.created_at,d.title document_title,d.is_active document_is_active
        FROM access_links al JOIN documents d ON d.id=al.document_id ORDER BY al.created_at DESC,al.id DESC`).all();
    const query = searchTerm(req.query.q);
    res.render('admin/accesses', { links: filterAccesses(links, query), totalLinks: links.length, query,
        baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}` });
});
module.exports = router;
