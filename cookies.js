const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken')

exports.initCookie = (name, value, expiresIn=null) => {
    Cookies.set(name, value)//, {/*expires: expiresIn, */sameSite: 'lax'} /*, path*/)
}

exports.setCookie= (cname, cvalue, exdays) => {
    const d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));
    let expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
  }

exports.getCookieInfo = (name) => {
    let ver
    token = Cookies.get(name)
    if(name === "AccessToken")
        ver = jwt.verify(name, process.env.ACCESS_TOKEN)
    else if(name === "RefreshToken")
        ver = jwt.verify(name, process.env.REFRESH_TOKEN)
    else
        return null
    return ver
}
