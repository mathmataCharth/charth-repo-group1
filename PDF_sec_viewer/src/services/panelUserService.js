'use strict';
const db = require('../config/database');
const { hashPassword } = require('../utils/hash');
const problem = message => Object.assign(new Error(message), { status: 400 });
function username(value) {
    if (typeof value !== 'string' || !/^[\p{L}\p{N}][\p{L}\p{N}._@ -]{2,63}$/u.test(value.trim())) throw problem('Informe um nome de usuário de 3 a 64 caracteres, usando letras, números, espaços, ponto, hífen ou sublinhado.');
    return value.trim();
}
function password(value, minimum = 6) {
    if (typeof value !== 'string' || value.length < minimum || Buffer.byteLength(value, 'utf8') > 72) throw problem(`A senha deve ter pelo menos ${minimum} caracteres e no máximo 72 bytes.`);
    return value;
}
async function createSectorUser(name, initialPassword) {
    const login = username(name), hash = await hashPassword(password(initialPassword));
    return db.transaction(() => {
        if (db.prepare('SELECT id FROM admin_users WHERE username=? COLLATE NOCASE').get(login)) throw problem('Este nome de usuário já está cadastrado.');
        return db.prepare(`INSERT INTO admin_users(username,password_hash,role,must_change_password)
            VALUES (?,?,'setor_atacado',1)`).run(login, hash).lastInsertRowid;
    }).immediate();
}
async function resetSectorPassword(id, initialPassword) {
    const hash = await hashPassword(password(initialPassword));
    const result = db.prepare(`UPDATE admin_users SET password_hash=?,must_change_password=1,auth_version=auth_version+1
        WHERE id=? AND role='setor_atacado'`).run(hash, id);
    if (!result.changes) throw problem('Usuário do setor atacado não encontrado.');
}
function toggleSectorUser(id) {
    const result = db.prepare(`UPDATE admin_users SET is_active=CASE WHEN is_active=1 THEN 0 ELSE 1 END,
        auth_version=auth_version+1 WHERE id=? AND role='setor_atacado'`).run(id);
    if (!result.changes) throw problem('Usuário do setor atacado não encontrado.');
}
module.exports = { createSectorUser, resetSectorPassword, toggleSectorUser, password };
