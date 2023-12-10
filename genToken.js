const crypto = require('crypto')

const genToken = () => return crypto.randomBytes(64).toString('hex')

module.exports = genToken
