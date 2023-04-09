const path = require('path');
const express = require('express');
const https = require('https');
const fs = require('fs');
// helmet是一个express中间件 保护信息的
// 真你妈是头盔啊
// 保护response的header
const helmet = require('helmet');
// 这里 npm install passport@0.5
const passport = require('passport');
const {Strategy} = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
const {verify} = require('crypto');

require('dotenv').config();
const PORT = 3000;

// 这里配置从Google拿到的clientID和clientSecret
const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
}
// 这里开始配置passport 在下面要用use 启动passport
const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    // 这个要和google 里面配置的一样
    // https://localhost:3000/auth/google/callback 这里是谷歌配置的
    // 官方文档
    // Google will redirect users to this location after they have authenticated.
    // The path of this URL must match the route defined below.
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
}

// 这个函数的触发是在浏览器送出token 然后google返回一个token 以后
function verifyCallback(accessToken, refreshToken, profile, done) {
    // 这一步好像是为了和数据库那边交互的
    console.log("google profile", profile);
    // 成功了返回一个done
      
    done(null, profile)
//     done: a function that is called when the authentication process is complete
}

// 要先配置passprot使用的strategy
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// save the session to cookie
// 第一次登录给你serialize
// servialized的时候会把user.id放到cookie里面
// 这个时候会给这些东西放到req.user里面  本质上是放到 req.session.passport.user里面
passport.serializeUser((user, done) => {
    done(null, user.id);
})
// 从cookie里面拿出来
// 这个顺序不是从上到下的顺序 这里的serialize和deserialize的顺序是走的另一条flow
// 第二次登录看你有 cookie 有就deserialize
// 当有req.body的时候会触发这个
// The general passport middleware we setup (passport.initialize) is invoked on the request,
// it finds the passport.user attached to the session.
// If is doesn't (user is not yet authenticated) it creates it like req.passport.user = {}.
// 如果找到了就会触发这个，并解析出来
// The passport.session middleware calls passport.deserializeUser we've setup.
// Attaching the loaded user object to the request as req.user.
passport.deserializeUser((id, done) => {
    // 这里好像可以和数据库交互
    done(null, id);
})

const app = express();
//在第一层use直接架上helmet
app.use(helmet());
// cookieSession要在passport之前
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]//这里类似于密码了
//     提供一堆key 这些key 在不同时段生效
}))

// 这里要启动passport
app.use(passport.initialize());
// 这里要启动passport的session
app.use(passport.session());

// 开始上session

function checkLogin(req, res, next) {
    console.log("checkLogin", req.user)//这里是serialize的时候放进去的，当调用的时候会触发deserialize
    const isLoggedIn = req.isAuthenticated()&& req.user
    if (!isLoggedIn) {
        return res.status(401).json({
            message: 'You are not logged in'
        })
    }
    next();
}

// app.use((req, res, next) => {
//     const isLoggedIn = true;
//     if (isLoggedIn) {
//         return res.status(401).json({
//             message: 'You are not logged in'
//         })
//     }
//     next();
// })

// 当我点击index页面的时候 先是触发这个link
app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']//他说可以拿到信息 但是拿到有什么用呢
    // 好像会限制请求里的scope 但是我不知道有什么用
    // scope: ['profile']//他说可以拿到信息 但是拿到有什么用呢
//     我试了一下 感觉没有任何区别，但是不写不行
}))

// 这里是google返回的callback 当验证以后Google会往这里打入
// 然后我们根据打入给往下面的网址引
app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true,
    //      操你妈 我括号加错位置了
    }), (req, res) => {
        console.log("google called us back")
    })


app.get('/failure', (req, res) => {
    return res.send('You failed to login with Google');
})
app.get('/auth/logout', (req, res) => {
    req.logout();//真简便啊。。。
    // 这行把session里面的value 给改了 虽然没有清理但是那个已经没用了
    return res.redirect('/');
})


// 可以自己加上自己的中间件
// 如何限制api访问
app.get('/secret', checkLogin, (req, res) => {
    return res.send('You found the secret page!');
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
})
// app.listen(PORT, () => {
//     console.log(`Server started on port ${PORT}`)
// })
// https://localhost:3000/
// 当我们这样设置以后 必须要加上https://才能运行

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Server started on port ${PORT}`)
});