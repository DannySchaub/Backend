require('dotenv').config()
const express = require("express")
const app = express()
app.use(express.json())

const jwt = require('jsonwebtoken')
const bcrypt = require("bcrypt")
const PORT = 3000

var tempUsers = []  //store in a database to keep away from attackers
var refreshTokens = []  //Implement cookies to keep away from attackers

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
        
        refreshTokens.push(refreshToken)
        res.json({message: "Successfully logged in.", accessToken: accessToken, refreshToken: refreshToken})

    } catch{
        res.status(401).send("Error occured while logging in.")
    }
})

app.post("/refreshToken", (req, res) => {
    const refreshToken = req.body.refreshToken

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

app.listen(PORT,  () => {
    console.log('> Ready on http://localhost:3000')
})