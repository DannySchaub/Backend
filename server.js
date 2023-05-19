require('dotenv').config()
const express = require("express")
const app = express()
app.use(express.json())

const {initCookie, getCookieInfo, setCookie} = require("./cookies.js")
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require("bcrypt")
const PORT = 3000

const baseURL = 'http://localhost:3000'

var tempUsers = []  //store in a database to keep away from attackers
var refreshTokens = []  //Implement cookies to keep away from attackers

app.use(cookieParser())

app.post('/create-user', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt()
        const hashedPass = await bcrypt.hashSync(req.body.password, salt)

        const user = {username: req.body.username, password: hashedPass}
        tempUsers.push(user)
        res.status(201).send("Successfully created your account.")
    }
    catch{
        res.status(500).send("Error.")
    }
})

app.get('/users', authenticateToken, (req, res) => {
    res.json(tempUsers.filter(user => user.username === req.user.username))
})

function authenticateToken(req, res, next){
    console.log(req.headers)
    const authHeader = req.headers.authorization
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null) 
        return res.status(401).send("Error getting token")

    jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
        if(err) 
            return res.status(403).send("Invalid Token")
        req.user = user
        next()
    })
}

app.post('/login', async (req, res) => {
    try{
        const user = tempUsers.find(user => user['username'] === req.body.username)
        if(user){
            try{
                if(await bcrypt.compare(req.body.password, user['password'])){
                    res.status(200)

                }
                else{
                    res.status(500).send("Incorrect Username/Password combination.")
                }
            } catch {
                res.send("hey, Error occured while logging in.")
            }
            
        }
        else{
            return res.status(400).send("Unable to find Username.")
        }
        
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '300s' })
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN)
        
        refreshTokens.push(refreshToken) //replace with cookies/database

        
        const today = new Date()
        res.cookie("RefreshToken", refreshToken, {
            expires: today.setFullYear(today.getFullYear + 3),
            httpOnly: true,
            sameSite: 'lax',
            secure: true
        })
        
        const tenMinutes = new Date(Date.now() + 600*1000)
        res.cookie("AccessToken", accessToken, {
            expires: tenMinutes,
            httpOnly: true,
            sameSite: 'lax',
            secure: true
        })
        
        res.json({message: "Successfully logged in.", accessToken: accessToken, refreshToken: refreshToken})
    } catch{
        res.status(401).send("Error occured while logging in.")
    }
})

app.get("/login", (req, res) => {
    res.send("Log in Here\nCreate Account here")
})

//http://localhost:3000/readCookies
app.get("/readCookies", (req, res) => {
    const accessToken = req.cookies['AccessToken']
    const refreshToken = req.cookies['RefreshToken']

    res.send(`Value of 'my-cookie' cookie: ${accessToken}\n${refreshToken}`)
})

//http://localhost:3000/loginRequest?username=Danny&password=secret
app.get("/loginRequest", (req, res) => {
    fetch(baseURL + "/login", {
        method: "POST", 
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            "username": req.query.username,
            "password": req.query.password
        })
    }).then(resp => {
        if (!resp.ok) {
            throw new Error('Failed to Log in');
        }
        return resp.json()
    }).then(data => {
        console.log('User logged in successfully') 
        console.log(data.cookie)
        res.send(
            "message:" + data.message +
            "\naccessToken:" + data.accessToken +
            "\nrefreshToken:" + data.refreshToken
        )
    }).catch(error => {
        res.send('Failed to Log in')
        console.error(error)
    })
})

//http://localhost:3000/create-user?username=Danny&password=secret
app.get('/create-user', (req, res) => {
    fetch(baseURL + "/create-user", {
        method: "POST", 
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            "username": req.query.username,
            "password": req.query.password
        })
    }).then(resp => {
        if (!resp.ok) {
            throw new Error('Failed to create user');
        }
        return resp
    }).then(data => {
        console.log('User created successfully')
        res.send("Successfully created your account.")
    }).catch(error => {
        res.send('Failed to create user')
        console.error(error)
    })
})

app.use("/", (req, res) => {
     res.send("Home Page")
})



app.post("/refreshToken", (req, res) => {
    const arr = document.cookie.split("; ")
    const refreshToken = arr["RefreshToken"]
    //const refreshToken = req.body.refreshToken

    if (refreshToken == null) 
        return res.status(401).send("Missing Refresh Token")
    if (!refreshTokens.includes(refreshToken)) 
        return res.status(403).send("Invalid Refresh Token")

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if (err) 
            return res.status(403).send("Invalid Refresh Token")
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '300s' })
        res.json({ message: "Generated new access token.", accessToken: accessToken })
  })
})

app.use('/logout', (req, res) => {
    tempUsers = tempUsers.filter(user => user !== req.body.user)
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.get('/cookies', (req, res) => {
    res.json(getCookieInfo("AccessToken"), getCookieInfo("RefreshToken"), getCookieInfo("notValid"))
})

app.listen(PORT,  () => {
    console.log('> Ready on http://localhost:3000')
})

