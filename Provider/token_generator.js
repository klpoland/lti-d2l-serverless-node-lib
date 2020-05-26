const { config } = require('./config.js')
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem')
const { create_unique_string } = require('./oidc.js')
const axios = require('axios')
const AWS = require('aws-sdk')
const qs = require('qs')
const crypto = require('crypto')
const request = require('request')

const dynamodb = new AWS.DynamoDB({apiVersion: '2012-08-10'})

/* 
Creates a JSON Web Token to be used to gain Access Token
*/
async function formatJWTforAccessToken(req) {

  //retrieve keys from our keyset endpoint
  const myKeys = await axios.get(config().clientUrl + "/.well-known/jwks")

  //get kid of key we want to use
  const kidToUse = myKeys.data.keys[0].kid
  console.log(kidToUse)

  //set up header for json web token to use in request
  const jwtHeader = {
    'typ': 'JWT',
    'alg': 'RS256',
    'kid': kidToUse
  }

  //TODO: This throws validation errors, check format of parameters
  //get private key from dynamodb
  const params = {
    ExpressionAttributeValues: {
      ':kid': {
        S: kidToUse
      }
    },
    KeyConditionExpression: 'kid = :kid',
    TableName: 'jwks-table'
  }

  //build jwt
  const client_assertion = await dynamodb.query(params).promise().then(function (result) {
    if (Object.keys(result).length !== 0) {
      const keyObj = result.Items[0]
      console.log(keyObj)
      let privateKey = {}

      for (item in keyObj) {
        if (item == 'exp') {
          privateKey[item] = keyObj[item].N
        } else {
          privateKey[item] = keyObj[item].S
        }
      }

      console.log('Private key object: ', privateKey)

      //payload for jwt
      const jwtPayload = {
        "iss" : req.session.platform_DBinfo.consumerToolClientID.S,
        "sub" : req.session.platform_DBinfo.consumerToolClientID.S,
        "aud" : req.session.platform_DBinfo.consumerUseTokenURL.S,
        "iat" : Math.floor(Date.now()/1000),
        "exp" : Math.floor(Date.now()/1000 + 30*60),
        "jti" : crypto.randomBytes(16).toString("hex")
      }

      console.log(jwtPayload)
      console.log(jwkToPem(privateKey, {private: true}))
      console.log(jwkToPem(myKeys.data.keys[0]))
      
      //encode and sign jwt
      const requestToken = jwt.sign(jwtPayload, jwkToPem(privateKey, {private: true}), {keyid: kidToUse, algorithm: 'RS256'})
      
      return requestToken

    } else {
      console.log(`No key with kid ${kidToUse}`)
    }
  })

  return client_assertion

}



function getAuthCode(req, res) {
  const authCodeEndpoint = "https://auth.brightspace.com/oauth2/auth"
  console.log(config())
  const authCodeParams = qs.stringify({
    response_type: "code",
    redirect_uri: config().clientUrl + "/valencetest",
    client_id: config().clientId,
    scope: "core:*:*",
    state: create_unique_string(30, false)
  })

  console.log("redirecting....")
  res.redirect(authCodeEndpoint + "?" + authCodeParams)
}

async function getAccessTokenValence(req, res) {
    const authCode = req.query.code
    console.log(req)
    console.log(authCode)
  
    const payload = qs.stringify({
      grant_type: "authorization_code",
      redirect_uri: config().clientUrl + "/valencetest",
      code: authCode
    })
  
    const creds = new Buffer(config().clientId + ":" + config().clientSecret).toString('base64')
    console.log(creds)
  
    const tokenResponse = await axios.post(config().accessTokenUrl, payload,
      { headers: {
        "Authorization": "Basic " + creds,
        "Content-Type": "application/x-www-form-urlencoded"
        }
    })
    .catch( err => console.log(err))

    return tokenResponse.data
}

//getting 500 error: "unknown exception ocurred"
function getAccessTokenLTI(req) {
  const clientAssertion = await formatJWTforAccessToken(req)
  console.log("Client Assertion: ", clientAssertion)

  //payload for the request for access token, using client assertion
  const payload = {
    'grant_type': 'client_credentials',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'scope': 'https://purl.imsglobal.org/spec/lti-ags/scope/lineitems', //route for request
    'client_assertion': clientAssertion
  }

  let token = await axios.post(req.session.platform_DBinfo.consumerAccessTokenURL.S, qs.stringify(payload), 
    { headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  })

  return token
}

module.exports = { formatJWTforAccessToken, getAuthCode, getAccessTokenValence, getAccessTokenLTI };
