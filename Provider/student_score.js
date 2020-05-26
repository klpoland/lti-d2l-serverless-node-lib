const axios = require('axios');
const qs = require('qs')
const { fromBase64, encode } = require('base64url');
const { formatJWTforAccessToken } = require('./token_generator.js')

//@param req - response from oidc launch

async function create_lineItem(req) {
  console.log(req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope)
  if (req.session.decoded_launch.hasOwnProperty('https://purl.imsglobal.org/spec/lti-ags/claim/endpoint') &&
  req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope.includes('https://purl.imsglobal.org/spec/lti-ags/scope/lineitem')) {
    
    console.log('Building code request.')

    const clientAssertion = await formatJWTforAccessToken(req)
    console.log("Client Assertion: ", clientAssertion)

    //payload for the request for access token, using client assertion
    const payload = {
      'grant_type': 'client_credentials',
      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'scope': 'https://purl.imsglobal.org/spec/lti-ags/scope/lineitems', //route for request
      'client_assertion': clientAssertion
    }

    //unknown 500 error, D2L says may be issue on their end
    await axios.post(req.session.platform_DBinfo.consumerAccessTokenURL.S, qs.stringify(payload), 
      { headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(async (result) => {
      console.log("result: ", result)
      //build lineItem request payload
      const lineItem = {
        'scoreMaximum': 100,
        'label': 'Test Quiz 1',
        'resourceLinkId': req.session.decoded_launch['https://purl.imsglobal.org/spec/lti/claim/resource_link'].id,
        'tag': 'test',
        'startDateTime': new Date(Date.now()),
        'endDateTime': new Date(Date.now() + 5*24*3600*1000)
      }; 
      await axios.post(req.session.payload["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].lineitems, 
        qs.stringify(lineItem), 
        { headers: {
          'Authorization': result.token_type + ' ' + result.access_token,
          'Content-Type': 'application/vnd.ims.lis.v2.lineitem+json'
      }})
      .then(success => console.log(success))  //successfully create line item
      .catch(err => console.log(err));   //error creating line item
    })
    .catch(err => console.log(err)); //error getting token

  } else {
    console.log('false')
    return false;
  }
}

/*
* Check if Platform allows scores to be sent, if it does, request Authorization Code
* @param payload - decoded Launch Request
* @returns boolean of whether sending scores is in scope or not
*/
function prep_send_score(req) {
  console.log(req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope)
  if (req.session.decoded_launch.hasOwnProperty('https://purl.imsglobal.org/spec/lti-ags/claim/endpoint') &&
  req.session.decoded_launch["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].scope.includes('https://purl.imsglobal.org/spec/lti-ags/scope/score')) {
    console.log('Building URL')
    const tokenUrl = code_request(req, 'https://purl.imsglobal.org/spec/lti-ags/scope/score');
    console.log(tokenUrl)
    return "Token URL created."
  } else {
    console.log('false')
    return false;
  }
}

/*
* Send score to Platform. Must get appropriate access token and then send score
* @param req 
* @param score - final score for student's work
* @param scoreMax - maximum score allowed for work
*/
function send_score(req, score, scoreMax) {
  //Request the access token
  const payload = {
    grant_type: 'authorization_code',
    code:  req.params.code,
    client_id:  req.session.platform_DBinfo.consumerToolClientID.S,
    redirect_uri: 'https://testing.appool.org/postGrades',
    scope: 'https://purl.imsglobal.org/spec/lti-ags/scope/score',
    code_verifier: req.session.code_verifier
  }
  const base64_user_pass = encode(req.session.platform_DBinfo.kid[0].keyID + ':' + req.session.platform_DBinfo.kid[0].privateKey, 'base64');
  
  axios.post(req.session.platform_DBinfo.consumerUseTokenUrl, payload, 
    { headers: {
      'Authorization': 'Basic ' + base64_user_pass,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  })
  .then(result => {
    //With access token, send score to Platform
    const score_message = {
      "userId":  req.session.payload.sub,
      "scoreGiven": score,
      "scoreMaximum": scoreMax,
      "timestamp": new Date(Date.now()).toJSON(),
      "activityProgress": "Completed",
      "gradingProgress": "FullyGraded"
    }; 
    axios.post(req.session.payload["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"].lineitem + "/scores", 
      score_message, 
      { headers: {
        'Authorization': result.token_type + ' ' + result.access_token,
        'Content-Type': 'application/vnd.ims.lis.v1.score+json'
    }})
    .then(success => console.log(success))  //successfully posted grade
    .catch(err => console.log(err));   //error posting grade
  })
  .catch(err => console.log(err)); //error getting token
}


module.exports = { prep_send_score, send_score, create_lineItem };
