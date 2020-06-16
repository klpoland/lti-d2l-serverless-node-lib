const { generateKeyPairSync } = require("crypto");
const crypto = require("crypto");
const jose = require('node-jose')
const AWS = require('aws-sdk')

const dynamodb = new AWS.DynamoDB({apiVersion: '2012-08-10'})
const cloudwatch = new AWS.CloudWatchEvents({apiVersion: '2015-10-7'})

/*
* Creates a unique pass phrase
* @returns phrase
*/
function passPhrase() {
  var phrase = "";
  var characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 255; i++) {
    phrase += characters.charAt(Math.random() * characters.length);
  }
  
  return phrase.toString();
}

/*
* Generate RSA public and private key pair to validate between Tool and the Platform
* @returns key pair
*  NOTE: The signature and the verification needs to be updated with a proper consumerID or some other unique identifer
*/
function keyGenerator() {
  var keys = {};
  var kid = passPhrase();

  const { publicKey, privateKey } = generateKeyPairSync(
    "rsa",
    {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: "spki",
        format: "pem"
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: kid
      }
    },
    (err, publicKey, privateKey) => {
      var sign = crypto.createSign("RSA-SHA256");
      sign.update("ConsumerClientID");
      const signature = sign.sign(privateKey, "base64");
      console.info("signature: %s", signature);

      const verify = crypto.createVerify("RSA-SHA256");
      verify.update("ConsumerClientID");
      const verified = verify.verify(publicKey, "base64");
      console.info("is signature ok? %s", verified);
    }
  );

  keys = { 'publicKey': { S: publicKey } , 'privateKey': { S: privateKey }, 'keyID': { S: kid } };
  return keys;
}

function createCronExpression(times) {
  let cronObj = {'min': '', 'hr': '', 'dom': '', 'mon': '', 'dow': '?', 'yr': ''}

  //get date information, all expire on same day
  genDate = new Date(times[0])
  cronObj.dom = genDate.getDate()
  cronObj.mon = genDate.getMonth() + 1
  cronObj.yr = genDate.getFullYear()

  for (i in times) {
    let unixTime = times[i]
    let date = new Date(unixTime)
    
    //add min and hr to cronObj
    if (unixTime != times[times.length - 1]) {
      cronObj.min += date.getMinutes() + ','
      cronObj.hr += date.getHours() + ','
    } else {
      cronObj.min += date.getMinutes()
      cronObj.hr += date.getHours()
    }
  }

  const cronExpression = `${cronObj.min} ${cronObj.hr} ${cronObj.dom} ${cronObj.mon} ${cronObj.dow} ${cronObj.yr}`
  return `cron(${cronExpression})`
}

async function createCWRule(times) {
  const ruleParams = {
    Name: 'update-keys',
    ScheduleExpression: createCronExpression(times),
    State: 'ENABLED'
  }
  await cloudwatch.putRule(ruleParams).promise().then(async () => {
    const targetParams = {
      Rule: 'update-keys',
      Targets: [
        {
          Arn: 'arn:aws:lambda:us-east-1:815203876747:function:update-jwks',
          Id: 'update-jwks-function'
        }
      ]
    }
    await cloudwatch.putTargets(targetParams).promise()
  })
}

async function jwksGenerator(num, times = []) {
  let keystore = jose.JWK.createKeyStore()
  const now = new Date()
  const timestamp = now.getTime()
  //set expTime to 7 days from "now" (time of creation)
  let expTime = timestamp + 7*24*3600*1000
  for (i = 0; i < num; i++) {
    const key = await jose.JWK.createKey("RSA", 2048, {alg: "rsa256", use: "sig", exp: expTime})
    await keystore.add(key).then(function(result) {
      privkey = result
    })
    times.push(expTime)
    //stagger expiration by 30 minutes so they don't all expire at once
    expTime += 30*60*1000
  }
  
  //create/update a cloudwatch rule that will run a function to update keys when they expire
  await createCWRule(times)

  return keystore.toJSON(true)
}

async function renderJWKSendpoint(res) {
  let params = {
    TableName: 'jwks-table'
  }

  await dynamodb.scan(params).promise().then(function (result) {
    if (Object.keys(result).length !== 0) {
      let pubkeys = {'keys': []}
      const keyList = result.Items
      for (i in keyList) {
        const key = keyList[i]
        const formattedKey = {'alg': key.alg.S, 'e': key.e.S, 'kid': key.kid.S, 'kty': key.kty.S, 'n': key.n.S, 'use': key.use.S, 'exp': key.exp.N}
        pubkeys.keys.push(formattedKey)
      }
      res.send(pubkeys)
    } else {
      res.send("No platform registered.")
    }
  })

}

module.exports = { keyGenerator, passPhrase, jwksGenerator, renderJWKSendpoint, createCWRule, createCronExpression };
