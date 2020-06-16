const express = require('express')
const sls = require('serverless-http')
const bodyParser = require('body-parser')
const session = require('express-session')
const b64 = require('base64url')

//lti-node-library
const { registerPlatform } = require('./Provider/register_platform.js');
const { renderJWKSendpoint } = require('./Provider/keyGenerator.js')
const { create_oidc_response, create_unique_string } = require("./Provider/oidc.js");
const { launchTool } = require('./Provider/launch_validation.js')

const app = express()

app.use(session({
  name: 'lti_v1p3_app_session',
  secret: create_unique_string(10, false),
  saveUninitialized: true,
  resave: true,
  secure: true,
  ephemeral: true,
  httpOnly: true
}));
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))
app.engine('html', require('ejs').renderFile)
app.set('view engine', 'ejs')
app.set('views', __dirname)

app.post('/authorize', async (req,res) => {

//register platform information given when you set up an app in the LTI Advantage tab
//to dynamodb, if one does not already exist

  await registerPlatform(
    config().hostUrl,
    'D2L',
    'client_id_from_platform',
    config().hostUrl + '/d2l/lti/authenticate',
    'https://auth.brightspace.com/core/connect/token',
    'https://api.brightspace.com/auth/token',
    config().clientUrl + '/redirect',
    {'method': { S: 'JWK_SET' }, 'key': { S: config().hostUrl + '/.well-known/jwks' } }
  )

//once platform is set up, using lti-node-library which I modified to run on lambda with serverless
//create oidc response is a function that queries the mongodb you set up to get platform information
//and combines it with a response from D2L that looks like this:
/*
{
  iss: platform url | string,
  login_hint: given by platform | string,
  target_link_uri: link to tool you want to launch | string,
  lti_deployment_id: given by platform | string,
  client_id: given by platform | string,
  lti_message_hint: given by platform | string
}
*/
//it uses this information to authorize user with platform authorization endpoint 
//and redirects to /redirect which was specified by the user upon setup of lti tool

  create_oidc_response(req, res)

})


//here is where user should be redirected with jwt ("id_token") in req.body (post request)
//run launchTool function from lti-node-library to verify the web token 
//(sig from private key must match public key)
//checks that all the required information is present with valid_launch_request() function
//redirects to target_link_uri, the url of the tool/app
//includes information like: user name, d2lid, ou, given name, etc. of requester specified in deployment setup
app.post('/redirect', (req, res) => {
  launchTool(req, res, '')
})

//boiler plate
app.get('/example', (req, res) => {
  console.log(req.session.decoded_launch)
  const launch_info = req.session.decoded_launch
  res.send(`Hello ${launch_info.name}, here is your user information: <br/>
            Your username is ${launch_info['http://www.brightspace.com'].username}.<br/>
            Your email is ${launch_info.email}.<br/>
            Your OrgUnitDefinedId is ${launch_info['http://www.brightspace.com'].org_defined_id}.<br/>
            Your D2LID is ${launch_info['http://www.brightspace.com'].user_id}`)
})

app.get('/.well-known/jwks', async (req, res) => {
  renderJWKSendpoint(res)
})

module.exports.server = sls(app)
