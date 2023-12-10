const bcrypt = require('bcrypt');

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};
const logPass = async (pass) => console.log(await hashPassword(pass));
logPass('test');
