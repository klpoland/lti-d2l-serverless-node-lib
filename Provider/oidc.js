require('dotenv').config();
const url = require('url');    
const AWS = require('aws-sdk')

const dynamodb = new AWS.DynamoDB({apiVersion: '2012-08-10'})

/*
* Validates OIDC login request.  Checkes required parameters are present.
* @param req - OIDC login request sent from LMS to Tool
* @returns array of errors, if empty then request is valid
*/
function is_valid_oidc_login(req) {
  let errors = [];
  if (!req.body.hasOwnProperty('iss')) {
    errors.push('Issuer missing');
  }
  if (!req.body.hasOwnProperty('login_hint')) {
    errors.push('Login hint missing');
  }
  if (!req.body.hasOwnProperty('target_link_uri')) {
    errors.push('Target Link URI missing');
  }
  return errors;
}

/* 
* Validate OIDC login and construct response for valid logins.  Looks up Issuer in database to ensure they are registered
* with the Tool.
* @param req - req sent from OIDC to Tool's OIDC login endpoint
* @returns if valid request, returns properly formated response object
* @return if invalid request, returns array of errors with the request
*/

function create_oidc_response(req, res) {
  let errors = [];

  //Save the OIDC Login Request to reference later during current session
  req.session.login_request = req.body;
  
  let params = {
    Key: {
      'consumerUrl': {
        S: req.session.login_request.iss
      }
    },
    TableName: 'platform-table'
  }

  dynamodb.getItem(params).promise().then( (platform) => {
    
    req.session.platform_DBinfo = platform.Item;

    errors = is_valid_oidc_login(req);

    if (errors.length === 0 && req.session.platform_DBinfo) {
      let response = {
        scope: 'openid',
        response_type: 'id_token', //id_token carries info about the user
        client_id: req.session.platform_DBinfo.consumerToolClientID.S, //given by D2L, for OIDC login
        redirect_uri: req.session.platform_DBinfo.consumerRedirect_URI.S, //given by D2L, where the JWT is sent after OIDC login
        login_hint: req.body.login_hint, //given by D2L, for OIDC login
        state: create_unique_string(30, true),
        response_mode: 'form_post',
        nonce: create_unique_string(25, false), //random character string, different for each request, prevents replay attacks
        prompt: 'none'
      }
      if (req.body.hasOwnProperty('lti_message_hint')) {
        response = {
          ...response,
          lti_message_hint: req.body.lti_message_hint,
        };
      }
      //Save the OIDC Login Response to reference later during current session
      req.session.login_response = response;

      //redirects OIDC login information to authorization endpoint on D2L
      //D2L verifies response and gives back a JWT which is sent to /redirect
      const redirectUrl = url.format({
        pathname: platform.Item.consumerAuthorizationURL.S, 
        query: req.session.login_response
      })

      res.redirect(redirectUrl);
    } else if (!req.session.platform_DBinfo) {
        errors.push('Issuer invalid: not registered');
    }

    //errors were found, so return the errors
    if (errors.length > 0) {
      res.send('Error with OIDC Login: ' + errors);
    }

  }).catch((err) => {
    console.log('Error occurred while trying to get platform: ', err)
  })
}

/*
* Create a long, unique string consisting of upper and lower case letters and numbers.
* @param length - desired length of string
* @param signed - boolean whether string should be signed with Tool's private key
* @returns unique string
*/
function create_unique_string(length, signed) {
  let unique_string = '';
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for(let i = 0; i < length; i++) {
    unique_string += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  //TODO: if signed === true, sign the string with our private key
  return unique_string;
}

module.exports = { create_oidc_response, create_unique_string };
