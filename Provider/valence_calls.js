const { config } = require('./config.js')
const { getAccessToken } = require('./token_generator')
const axios = require('axios')
const qs = require('qs')

async function getVersionsCall(req, res) {

  const tokenObj = await getAccessToken(req, res)

  const result = await axios.get(config().hostUrl + "/d2l/api/versions/", {
    headers: {
      "Authorization": tokenObj.token_type + ' ' + tokenObj.access_token
    }
  })
  .then(success => {
    console.log(success.data)
    const versions = {}
    
    for (i in success.data) {
      versions[success.data[i].ProductCode] = success.data[i].LatestVersion
    }

    return {'data': versions, 'token': tokenObj}
  })
  .catch(err => console.log(err))

  return result

}

async function whoAmICall(req, res) {
  
  const versionData = await getVersionsCall(req, res)


  axios.get(config().hostUrl + "/d2l/api/lp/" + versionData.data.lp + "/users/whoami", {
    headers: {
      "Authorization": versionData.token.token_type + ' ' + versionData.token.access_token
    }
  })
  .then(success => {
    console.log(success.data)
    res.redirect(config().clientUrl + "/finish")
  })
  .catch(err => console.log(err))

}

module.exports = { getVersionsCall, whoAmICall };