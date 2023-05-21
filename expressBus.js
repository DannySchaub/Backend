require('dotenv').config()
const express = require("express")
const cookieParser = require('cookie-parser')
const useRefreshToken = require("./auth")

configureApp = (app) => {
    //app.use(routeOptions())
    app.use(express.json())
    app.use(cookieParser())
    //app.use(useRefreshToken())
}

// routeOptions = (req, res, next) => {
//     res.message = "None"
// }

module.exports = configureApp