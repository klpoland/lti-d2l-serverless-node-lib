const AWS = require('aws-sdk')
const { jwksGenerator, keyGenerator } = require('./keyGenerator.js');

const dynamodb = new AWS.DynamoDB({apiVersion: '2012-08-10'})

const registerJWKS = async () => {
  //creates/updates jwks database
  const keySet = await jwksGenerator(4);
  for (i in keySet.keys) {
    const key = keySet.keys[i]
    let jwksParams = {Item: {}, TableName: 'jwks-table'}
    for (j in Object.keys(key)) {
      const objKey = Object.keys(key)[j]
      const value = key[objKey]
      if (objKey == 'exp') {
        jwksParams.Item[objKey] = {N: value.toString()}
      } else {
        jwksParams.Item[objKey] = {S: value}
      }
    }
    await dynamodb.putItem(jwksParams).promise().catch((err) => {
      if (err) console.log(err, err.stack);
    })
  }
}

/*
* Register a new Platform for the Tool
* @params - all of the Platform/Tool fields shown below
* @returns Platform object, if Platform is already registered
*/
const registerPlatform = async (
  consumerUrl, /* Base url of the LMS. */
  consumerName, /* Domain name of the LMS. */
  consumerToolClientID, /* Client ID created from the LMS. */
  consumerAuthorizationURL, /* URL for LMS authentication endpoint */
  consumerAccessTokenURL, /* URL that the LMS redirects to obtain an access token */
  consumerUseTokenURL, /* URL that the LMS redirects to use an access token */
  consumerRedirect_URI, /* URL that the LMS redirects to launch tool */
  consumerAuthorizationconfig, /* Authentication method and key for verifying messages from the platform. {method: "RSA_KEY", key:"PUBLIC KEY..."} */
) => {
  if ( !consumerUrl || !consumerName || !consumerToolClientID || !consumerAuthorizationURL || !consumerAccessTokenURL || !consumerRedirect_URI || !consumerAuthorizationconfig ) {
    console.log('Error: registerPlatform function is missing argument.');
  };
  let existingPlatform;

  //checks database for existing platform.
  let params = {
    Key: {
      'consumerUrl': {
        S: consumerUrl
      }
    },
    TableName: 'platform-table'
  }

  await dynamodb.getItem(params).promise().then( async (registeringPlatform) => {
    if (Object.keys(registeringPlatform).length === 0) {
      console.log('Registering new platform...')

      //register jwks
      await registerJWKS()
      // creates/inserts platform data into database.
      let platformParams = {
        Item: {
          'consumerUrl': {
            S: consumerUrl
          },
          'consumerName': {
            S: consumerName
          },
          'consumerToolClientID': {
            S: consumerToolClientID
          },
          'consumerAuthorizationURL': {
            S: consumerAuthorizationURL
          },
          'consumerAccessTokenURL': {
            S: consumerAccessTokenURL
          },
          'consumerUseTokenURL': {
            S: consumerUseTokenURL
          },
          'consumerRedirect_URI': {
            S: consumerRedirect_URI
          },
          'consumerAuthorizationconfig': {
            M: consumerAuthorizationconfig
          },
        },
        TableName: 'platform-table'
      }
      
      await dynamodb.putItem(platformParams).promise().catch((err) => {
        if (err) console.log(err, err.stack);
      })
  
      return console.log(`Platform registered at: ${consumerUrl}`);
      
    } else {
      console.log('Platform already registered, using existing platform.')
      existingPlatform = registeringPlatform;
      return existingPlatform
    };
  }).catch((err) => console.log("Error occurred while registering platform: ", err))

};

module.exports = { registerPlatform, registerJWKS };
