const axios = require('axios');
const { createHash } = require('crypto');
const { fromBase64, encode } = require('base64url');
const { passPhrase } = require('../Provider/keyGenerator');

/*
* Check if Platform allows scores to be sent, if it does, request Authorization Code
* @param payload - decoded Launch Request
* @returns boolean of whether sending scores is in scope or not
*/
function prep_get_roles(req) {
  console.log(req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope)
  if (req.session.decoded_launch.hasOwnProperty('https://purl.imsglobal.org/spec/lti-ags/claim/endpoint') &&
  req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope.includes('https://purl.imsglobal.org/spec/lti-ags/scope/score')) {
    console.log('Building code request.')
    console.log('code req: ', code_request(req, 'https://purl.imsglobal.org/spec/lti-ags/scope/score'))
    return code_request(req, 'https://purl.imsglobal.org/spec/lti-ags/scope/score');
  } else {
    console.log('false')
    return false;
  }
}

/*
* Creates appropriate payload to request Authorization code for provided scope
* @param req - original Request
* @param scope - scope requested
* @return - endpoint with parameters
*/
function code_request(req, scope) {
  const code_verifier = passPhrase();
  req.session.code_verifier = code_verifier;
  
  const payload = {
    response_type: 'code',
    client_id: req.session.platform_DBinfo.consumerToolClientID.S,
    redirect_uri: 'https://testing.appool.org/postGrades',
    scope: scope, //route for request
    state: passPhrase(),
    code_challenge: generate_challenge(code_verifier), 
    code_challenge_method: 'S256'
  };

  //console.log(req.session.platform_DBinfo)
  return req.session.platform_DBinfo.consumerAuthorizationURL.S + '?' + Object.keys(payload).map(key => key + '=' + payload[key]).join('&');
}

/*
* Create BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
* @param code_verifier - random string to endcode
* @returns encoded challenge
*/
function generate_challenge(code_verifier) {
  const hash = createHash('sha256')
      .update(code_verifier)
      .digest('base64');
  return fromBase64(hash);
}

/*
* Send score to Platform. Must get appropriate access token and then send score
* @param req 
* @param score - final score for student's work
* @param scoreMax - maximum score allowed for work
*/
function get_roles(req, score, scoreMax) {

  const score_message = {
    "userId":  req.session.decoded_launch['http://www.brightspace.com'].user_id,
    "scoreGiven": score,
    "scoreMaximum": scoreMax,
    "timestamp": new Date(Date.now()).toJSON(),
    "activityProgress": "Completed",
    "gradingProgress": "FullyGraded"
  }; 
  
  axios.post(req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].lineitem + "/scores", 
    score_message, 
    { headers: {
      'Authorization': 'Bearer ' + req.session.payload.id_token,
      'Content-Type': 'application/vnd.ims.lis.v1.score+json'
  }})
  .then(success => console.log(success))  //successfully posted grade
  .catch(err => console.log(err));   //error posting grade
}

module.exports = { prep_get_roles, get_roles };
