SECRET_TOKEN = '3b6ebdf6bdf0e273e5857ed22c4f64ef7626e067e989e9c17a3c7335b0cee7b5f16b3eb0bcf0fbe98e89ce0699b2e5453c97622281f72a7709ab201a45b192bd';
REFRESH_SECRET_TOKEN = '86855d7447717405075e775accd776ef8d56b5bbccf42bde145863d4596b2a924d8792b78094899c4d8c4dc5a50225e4f43592a43179bd3147df946a77364a41';

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const createHttpError = require('http-errors');

const administrtor = ['admin'];

/* 
{
    "username": "admin",
    "password": "test"
}
*/
const USERS = [
    {
        username: 'admin',
        password: '$2b$10$l.1nV2bFMDIWzY9TIVLmI.ZKH791GmeVs8OpEWnNLdo5qby9fdwmW',
    },
];

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};
const logPass = async (pass) => console.log(await hashPassword(pass));
logPass('test');

async function authUser(body) {
    const user = USERS.find((user) => user.username === body.username);

    if (user == null) throw { code: 400, msg: 'Cannot find user' };
    if (await bcrypt.compare(body.password, user.password)) {
        return { username: body.username };
    } else {
        throw { code: 403, msg: 'Not Allowed' };
    }
}

function authToken(req, res, next) {
    let authHeader, token;

    if (req.headers['authorization']) {
        authHeader = req.headers['authorization'];
        token = authHeader && authHeader.split(' ')[1];
    }

    if (req.cookies.user) token = req.cookies.user;

    if (token == null || token == undefined) return next(createHttpError(401, { message: 'Missing token' }));

    return jwt.verify(token, SECRET_TOKEN, (err, user) => {
        if (err) return next(createHttpError(403, { message: 'Access Denied' }));

        const admin = administrtor.find((name) => name == user.name);
        if (admin == null) return next(createHttpError(403, { message: 'This User is not allowed' }));

        return next();
    });
}

function generateAccessToken(user) {
    return jwt.sign(user, SECRET_TOKEN, { expiresIn: '1h' });
}

async function login(req, res, next) {
    try {
        const user = await authUser(req.body);

        const token = generateAccessToken({ name: user.username });
        const refToken = jwt.sign({ name: user.username }, REFRESH_SECRET_TOKEN);

        req.token = {
            accessToken: token,
            refreshToken: refToken,
        };
        next();
    } catch (error) {
        if (error.msg) return next(createHttpError(error.code, { message: error.msg }));
        else return next(createHttpError(500, { message: 'Internal Error' }));
    }

    return;
}

module.exports = {
    login,
    authToken,
};
