'use strict';

const panelAuth = require('./panelAuth');
function adminAuth(req, res, next) {
    return panelAuth(req, res, () => {
        if (req.panelUser.role !== 'admin') return res.status(403).send('Você não tem permissão para esta ação.');
        next();
    });
}

module.exports = adminAuth;
