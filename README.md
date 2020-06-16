# lti-node-lib
Adapted to work with AWS and DynamoDB from https://github.com/SanDiegoCodeSchool/lti-node-library

The LMS in mind for this library is D2L/Brightspace and it uses OAuth 2.0 for setting up Valence calls

To Use:

1. 
```
git clone
```
2. 
```
npm install
```
3. Create a config.js file in the Provider folder and copy and paste this code:

```javascript
module.exports.config = () => {
    const config = {
        clientId: '',
        clientSecret: '',
        hostUrl: '',
        accessTokenUrl: 'https://auth.brightspace.com/core/connect/token',
        callback: '',
        clientUrl: ''
    }
    return config
}
```
Then paste your Client ID and Secret received from setting up OAuth 2.0 on your LMS platform, the callback URL you provided to set up OAuth 2.0, the host URL of your LMS, and the base URL where your application will run.

In my case, both the client URL and the callback URL for OAuth 2.0 were set up using API Gateway on AWS.

4. Now look at the app.js file:

