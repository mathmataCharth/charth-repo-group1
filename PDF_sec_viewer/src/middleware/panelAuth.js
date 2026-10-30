'use strict';
const crypto = require('crypto');
const db = require('../config/database');
function panelAuth(req, res, next) {
    if (!req.panelUser) {
        const user = req.session?.adminId && db.prepare(`SELECT id,username,role,is_active,must_change_password,auth_version
            FROM admin_users WHERE id=?`).get(req.session.adminId);
        const version = req.session?.panelAuthVersion;
        const legacyAdmin = user?.role === 'admin' && user.auth_version === 0 && version === undefined;
        if (!user || !user.is_active || !['admin', 'setor_atacado'].includes(user.role) ||
            !legacyAdmin && version !== user.auth_version) {
            if (req.session) { delete req.session.adminId; delete req.session.adminUsername; delete req.session.panelAuthVersion; delete req.session.panelCsrf; }
            if (/\/preview(?:\/revisions\/\d+)?\/.+/.test(req.originalUrl)) return res.status(401).json({ error: 'Entre no painel para continuar.' });
            return res.redirect('/admin/login');
        }
        req.panelUser = user;
    }
    if (req.panelUser.must_change_password && req.originalUrl.split('?')[0] !== '/admin/account/password') {
        return res.redirect('/admin/account/password');
    }
    if (!req.session.panelCsrf) req.session.panelCsrf = crypto.randomBytes(32).toString('hex');
    res.locals.panelUser = req.panelUser;
    res.locals.panelCsrf = req.session.panelCsrf;
    next();
}
function csrf(req, res, next) {
    const token = req.body?._csrf, expected = req.session?.panelCsrf;
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || typeof expected !== 'string' || token.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) return res.status(403).send('Solicitação inválida. Atualize a página e tente novamente.');
    next();
}
panelAuth.csrf = csrf;
module.exports = panelAuth;
