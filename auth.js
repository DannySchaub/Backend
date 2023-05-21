require('dotenv').config()
const express = require("express")
const jwt = require('jsonwebtoken')



useRefreshToken = (req, res) => {
    const obj = req.cookies
    const refreshToken = obj["RefreshToken"]
    
    if (refreshToken == null) 
        return res.status(401).send("Missing Refresh Token")
    // if (!refreshTokens.includes(refreshToken)) 
    //     return res.status(403).send("Invalid Refresh Token")
    
    return jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if (err) 
            return res.status(403).send("Invalid Refresh Token")
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '600s' })
        return accessToken
  })
}

authenticateToken = (req, res, next) => {
    const obj = req.cookies
    const token = obj["AccessToken"]

    if(token == null || token == 'undefined'){ 
        try{
            const accessToken = useRefreshToken(req, res)
            
            const tenMinutes = new Date(Date.now() + 600*1000)
            res.cookie("AccessToken", accessToken, {
                expires: tenMinutes,
                httpOnly: true,
                sameSite: 'lax',
                secure: true
            })
            
            jwt.verify(accessToken, process.env.ACCESS_TOKEN, (err, user) => {
                if(err) 
                    return res.status(403).send("Invalid Token")
                req.user = user
                next()
            })
            
        }catch(err){
            return res.status(401).send(err)
        }
    }
    else{
        jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
            if(err) 
                return res.status(403).send("Invalid Token")
            req.user = user
            next()
        })
    }
}

module.exports = { useRefreshToken, authenticateToken }