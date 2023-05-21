require('dotenv').config()
const express = require("express")
const app = express()

const { authenticateToken } = require("./auth")
const configureApp = require('./expressBus')
const jwt = require('jsonwebtoken')
const bcrypt = require("bcrypt")
const PORT = 3000

const baseURL = 'http://localhost:3000'

var tempUsers = []  //store in a database to keep away from attackers
var refreshTokens = []  //Implement cookies to keep away from attackers/ + Database to store them?

configureApp(app)

app.post('/create-user', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt()
        const hashedPass = bcrypt.hashSync(req.body.password, salt)

        const user = {username: req.body.username, password: hashedPass}
        tempUsers.push(user)
        res.status(201).send("Successfully created your account.")
    }
    catch{
        res.status(500).send("Error.")
    }
})

app.get('/users', authenticateToken, (req, res) => {
    const user = tempUsers.find(user => user['username'] === req.body.username)
    res.send('Authorized access token ' + 
    "message:" + res.message
    )
})

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
        
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '600s' })
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN)
        
        refreshTokens.push(refreshToken) //replace with cookies/database

        res.status(200).send({message: "Successfully logged in.", accessToken: accessToken, refreshToken: refreshToken})
    } catch{
        res.status(401).send("Error occured while logging in.")
    }
})

app.get("/login", (req, res) => {
    res.send("Log in Here\nCreate Account here")
})

//http://localhost:3000/readCookies
app.get("/readCookies", (req, res) => {
    const obj = req.cookies
    const accessToken = obj["AccessToken"]
    const refreshToken = obj["RefreshToken"]

    res.send(`Value of 'AccessToken' cookie: ${accessToken}\nValue of 'RefreshToken': ${refreshToken}`)
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

        const today = new Date()
        res.cookie("RefreshToken", data.refreshToken, {
            expires: today.setFullYear(today.getFullYear + 3), //expires in three years
            httpOnly: true,
            sameSite: 'lax',
            secure: true
        })
        
        const tenMinutes = new Date(Date.now() + 600*1000)
        res.cookie("AccessToken", data.accessToken, {
            expires: tenMinutes,
            httpOnly: true,
            sameSite: 'lax',
            secure: true
        })

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

app.get("/", (req, res) => {
    res.send("Home Page")
})

// app.use('/logout', (req, res) => {
//     tempUsers = tempUsers.filter(user => user !== req.body.user)
//     refreshTokens = refreshTokens.filter(token => token !== req.body.token)
//     res.sendStatus(204)
// })

app.listen(PORT,  () => {
    console.log('> Ready on http://localhost:3000')
})

