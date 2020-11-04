const crypto = require('crypto');

const ALGORITHIM = 'aes-256-gcm';
const BLOCK_SIZE = 16;


/**
 * 
 * @param {string|Buffer} data 
 */
function createMD5Hash(data) {
    return crypto.createHash('md5').update(data, 'utf8').digest('hex');
}


/**
 * 
 * @param {string} passphrase 
 * @param {string|Buffer} data 
 */
function encrypt(passphrase, data) {
    let encrypted;
    const key = createMD5Hash(passphrase).substr(0, 32);
    const iv = crypto.randomBytes(BLOCK_SIZE);
    const cipher = crypto.createCipheriv(ALGORITHIM, key, iv);
    encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return iv.toString('hex') + authTag.toString('hex') + encrypted;
}


/**
 * 
 * @param {string} passphrase 
 * @param {string|Buffer} data 
 */
function decrypt(passphrase, data) {
    let decrypted;
    const key = createMD5Hash(passphrase).substr(0, 32);
    const content = Buffer.from(data, 'hex');
    const iv = content.slice(0, BLOCK_SIZE);
    const authTag = content.slice(BLOCK_SIZE, BLOCK_SIZE * 2);
    const text = content.slice(BLOCK_SIZE * 2).toString('hex');
    const decipher = crypto.createDecipheriv(ALGORITHIM, key, iv);
    decipher.setAuthTag(authTag);
    decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}


module.exports = {
    createMD5Hash,
    encrypt,
    decrypt
}