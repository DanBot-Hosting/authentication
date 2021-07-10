require('dotenv').config();
const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser')
const fetch = require('node-fetch');
const rateLimit = require("express-rate-limit");
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const redis = require('async-redis');

const { sendEmail } = require('./email');
const { Verify } = require('crypto');

const saltRounds = 10;

const authDatabase = redis.createClient({
    host: process.env.REDIS_host,
    port: process.env.REDIS_port,
    password: process.env.REDIS_password
});

const verification = new Map();

const garbageCollector = setInterval( () => {
    Array.from(verification.keys()).forEach( (key) => {
        const data = verification.get(key);
        console.log(key, data);
        if (Date.now() - data.created > 1000 * 60 * 30) verification.delete(key);
    });
}, 1000 * 60 * 5);

const services = new Map();
// services.set('cloud', 'http://192.168.0.27:3000/callback');
services.set('cloud', 'https://danbot.cloud/callback');
services.set('host', 'https://danbot.host/callback');
services.set('test', 'https://freddie.pw/callback');
Array.from(services.keys()).forEach(e => services.set(services.get(e), e));

// const [rows, fields] = await connection.execute('SELECT * FROM `table` WHERE `name` = ? AND `age` > ?', ['Morty', 14]);
let connection;

(async () => {
    connection = await mysql.createPool({
        host: process.env.DB_host,
        port: process.env.DB_port,
        user: process.env.DB_user,
        password: process.env.DB_password,
        database: process.env.DB_database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });
})()


const getToken = (tokenLength = 30) => {
    const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstwxyz1234567890";
    var token = "";
    while (token.length < tokenLength) {
        token += ALPHANUMERIC[Math.floor(Math.random() * ALPHANUMERIC.length)];
    }
    return token;
}

const runMysql = (q, p = []) => new Promise((res, rej) => {
    connection.query(q, p, function(err, rows, fields) {
        console.log(err)
        res(rows);
      });
});

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
};

const checkCaptchaResponse = (response, remoteip) => fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.captchaSecret}&response=${response}&remoteip=${remoteip}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'} 
    })
    .then((res) => res.json());

const loginLimiter = rateLimit({
    windowMs: 30 * 1000, // 30 seconds
    max: 5, // limit each IP to 10 requests per windowMs
    handler: (req, res) => {
        if (req.body.service) return  res.redirect(`${req.path}?service=${req.body.service}&error=Wowh slow down there, please wait before sending more requests!`);
        res.redirect(`${req.path}?error=Wowh slow down there, please wait before sending more requests!`)
    }
});

const sendVerifyEmail = async (email, username, ip, reason, serviceURL) => {
    const token = getToken();

    verification.set(token, {
        created: Date.now(),
        email,
        serviceURL,
        reason
    });

    if (reason == 'verifyEmail') {
        let content = await fs.promises.readFile('./mail/verifyEmail.html', 'utf8');
        await sendEmail(email, 'Verify your email | DBH', content
            .replace('{username}', username)
            .replace('{link}', `${process.env.url}/verify/${token}`)
            .replace('{ip}', ip)
            .replace('{time}', new Date().toString())
        );


    } else if ( reason == 'resetPassword' ) {
        console.log('Reset Pass')
        let content = await fs.promises.readFile('./mail/passwordReset.html' ,'utf8');
        await sendEmail(email, 'Reset your password | DBH', content
            .replace('{username}', username)
            .replace('{link}', `${process.env.url}/verify/${token}`)
            .replace('{ip}', ip)
            .replace('{time}', new Date().toString())
        );
    };

    console.log(token);
    return token;
};

const createAuthToken = async (user) => {
    const token = getToken(100);

    await authDatabase.set(token, JSON.stringify({
        ID: user.ID,
        username: user.username,
        email: user.email,
        phone: user.phone,
        created: user.created,
        discordID: user.discordID,
        phoneVerified: user.phoneVerified == 1,
        beta: user.beta == 1,
        admin: user.admin == 1,
        banned: user.banned == 1,
    }));

    await authDatabase.expire(token, 60 * 60 * 24);

    return token;
};  

const app = express();

app.use(express.static('public'));

app.use(async (req, res, next) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST");

    console.log(
        (req.headers["cf-connecting-ip"] ||
            req.headers["x-forwarded-for"] ||
            req.ip) +
        " [" +
        req.method +
        "] " +
        req.url
    );
            next();
});

app.get('/login', (req, res) => {
    fs.createReadStream('./pages/login.html').pipe(res);
});
app.get('/register', (req, res) => {
    fs.createReadStream('./pages/register.html').pipe(res);
});
app.get('/reset', (req, res) => {
    fs.createReadStream('./pages/reset.html').pipe(res);
});
app.get('/reset/new-password', (req, res) => {
    fs.createReadStream('./pages/reset-new.html').pipe(res);
});
app.get('/verify', (req, res) => {
    fs.createReadStream('./pages/verify.html').pipe(res);
});
app.get('/verify/:token', async (req, res) => {
    const data = verification.get(req.params.token);
    if (!data) return res.send('Expired token!');

    if (data.reason === 'resetPassword') {
        return res.redirect(`/reset/new-password?token=${req.params.token}`);
    };

    //confirm email code
    await runMysql('UPDATE users SET verified = true WHERE email = ? ;', [data.email]);

    const userData = await runMysql('SELECT * FROM `users` WHERE `email` = ?', [data.email]);
    if (userData.length == 0) return
    const token = await createAuthToken(userData[0]);

    verification.delete(req.params.token);
    res.redirect(`${data.serviceURL}?code=${token}`);

});
app.get('*', (req, res) => {
    res.redirect('/login');
});

app.use(bodyParser.urlencoded({ extended: false }));

app.use(loginLimiter);

app.post('/register', async (req, res) => {
    //input validation
    let { username, email, service } = req.body;
    const g_recaptcha_response = req.body['g-recaptcha-response'];
    const new_password = req.body['new-password'];
    const confirm_password = req.body['confirm-password'];
    if (!username || !email || !service || !g_recaptcha_response || !new_password || !confirm_password) return res.sendStatus(400);
    username = username.toLowerCase();
    email = email.toLowerCase();
    const serviceURL = services.get(service);
    if (!serviceURL) return res.redirect(`?`);
    if (username.length < 3 || username.length > 20 ) return res.redirect(`?service=${service}&error=Usernames must be between 3 and 20 characters`);
    if (!validateEmail(email) ) return res.redirect(`?service=${service}&error=Enter a valid email`);
    if (new_password.length < 8 || new_password.length > 30 ) return res.redirect(`?service=${service}&error=Passwords must be between 8 and 30 characters`);
    if (new_password !== confirm_password) return res.redirect(`?service=${service}&error=Those passwords do not match!`);
    
    //captcha
    const captchaResponse = await checkCaptchaResponse(g_recaptcha_response, req.ip);
    if (captchaResponse.success === false) return res.redirect(`?service=${service}&error=An error ocurred try again`);
    if (captchaResponse.score < 0.5 ) return res.redirect(`?service=${service}&error=An error ocurred try again`);

    const isUsernameTaken = await runMysql('SELECT count(username), count(email) FROM `users` WHERE `username` = ? OR `email` = ?', [username, email]);

    if (isUsernameTaken[0]['count(username)'] !== 0) return res.redirect(`?service=${service}&error=That username is taken!`);
    if (isUsernameTaken[0]['count(email)'] !== 0) return res.redirect(`?service=${service}&error=That email is taken!`);

    const hashedPassword = await bcrypt.hash(new_password, saltRounds);
    
    // const hashedPassword = await bcrypt.hash(new_password, saltRounds);

    await runMysql('INSERT INTO `users` (`username`, `email`, `password`) VALUES ( ? , ? , ? );', [username, email, hashedPassword]);

    //send email code

    await sendVerifyEmail(email, username, req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"] || req.ip, 'verifyEmail', serviceURL);
    return res.redirect(`/verify?email=${email}`);
});


app.post('/login', async (req, res) => {
    let { username, service } = req.body;
    const g_recaptcha_response = req.body['g-recaptcha-response'];
    const current_password = req.body['current-password'];

    if (!username || !service || !g_recaptcha_response || !current_password) return res.sendStatus(400);

    username = username.toLowerCase();
    const serviceURL = services.get(service);
    if (!serviceURL) return res.redirect(`?`);

    const captchaResponse = await checkCaptchaResponse(g_recaptcha_response, req.ip);
    if (captchaResponse.success === false) return res.redirect(`?service=${service}&error=An error ocurred try again`);
    if (captchaResponse.score < 0.5 ) return res.redirect(`?service=${service}&error=An error ocurred try again`);
    
    const userData = await runMysql('SELECT * FROM `users` WHERE `username` = ? OR `email` = ? ;', [username, username]);

    if (userData.length === 0) return res.redirect(`?service=${service}&error=Wrong username/email or password`);
    const hashedPassword = await bcrypt.compare(current_password, userData[0].password);
    if (!hashedPassword) return res.redirect(`?service=${service}&error=Wrong username/email or password`);

    const user = userData[0];
    if (!user.verified) {
        await sendVerifyEmail(user.email, userData[0].username, req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"] || req.ip, 'verifyEmail', serviceURL);
        return res.redirect(`/verify?email=${user.email}`);
    };

    const token = await createAuthToken(user);

    res.redirect(`${serviceURL}?code=${token}`);
});

app.post('/reset', async (req, res) => {
    let { email, service } = req.body;
    const g_recaptcha_response = req.body['g-recaptcha-response'];

    if ( !g_recaptcha_response || !email ) return res.sendStatus(400);

    email = email.toLowerCase();
    const serviceURL = services.get(service);
    if (!serviceURL) return res.redirect(`?`);

    const captchaResponse = await checkCaptchaResponse(g_recaptcha_response, req.ip);
    if (captchaResponse.success === false) return res.redirect(`?service=${service}&error=An error ocurred try again`);
    if (captchaResponse.score < 0.5 ) return res.redirect(`?service=${service}&error=An error ocurred try again`);

    const userData = await runMysql('SELECT * FROM `users` WHERE `email` = ? ;', [email]);

    if (userData.length === 0) return res.redirect(`?service=${service}&error=There is no account with that email!`);

    sendVerifyEmail(email, userData[0].username, req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"] || req.ip, 'resetPassword', serviceURL, 'To reset your password please verify your identity with');

    return res.redirect(`/verify?email=${email}`);
});

app.post('/reset-new', async (req, res) => {
    const { token } = req.body;
    const g_recaptcha_response = req.body['g-recaptcha-response'];
    const new_password = req.body['new-password'];
    const confirm_password = req.body['confirm-password'];

    if ( !g_recaptcha_response || !new_password || !confirm_password || !token ) return res.sendStatus(400);


    const captchaResponse = await checkCaptchaResponse(g_recaptcha_response, req.ip);
    if (captchaResponse.success === false) return res.redirect(`/reset/new-password?token=${token}&error=An error ocurred try again`);
    if (captchaResponse.score < 0.5 ) return res.redirect(`/reset/new-password?token=${token}&error=An error ocurred try again`);

    if (new_password.length < 8 || new_password.length > 30 ) return res.redirect(`/reset/new-password?error=Passwords must be between 8 and 30 characters&token=${token}`);
    if (new_password !== confirm_password) return res.redirect(`/reset/new-password?error=Those passwords do not match!&token=${token}`);


    const data = verification.get(token);
    if (!data) return res.send('Expired token!');

    const hashedPassword = await bcrypt.hash(new_password, saltRounds);

    const userData = await runMysql('UPDATE `users` SET `password` = ? WHERE `email` = ? ;', [hashedPassword, data.email]);

    verification.delete(token);
    return res.redirect(`/login?service=${services.get(data.serviceURL)}&error=Password reset`);
});

app.listen(process.env.port, () => {
    console.log(`[DBH] Auth server listening on port ${process.env.port}`);
});