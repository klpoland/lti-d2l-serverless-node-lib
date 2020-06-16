# lti-node-lib
Adapted to work with AWS and DynamoDB from https://github.com/SanDiegoCodeSchool/lti-node-library

The LMS in mind for this library is D2L/Brightspace and it uses OAuth 2.0 for setting up Valence calls

To Use:

### 1. Clone this repository:
```
git clone https://github.com/klpoland/lti-node-lib.git
```
### 2. Install required libraries to working directory:
```
npm install
```
### 3. Create a config.js file in the Provider folder and copy and paste this code:

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

### 4. Now look at the app.js file. It includes four Express endpoints:
    
* /authorize for registering your platform on DynamoDB and sending login information to OIDC (e.g. login_hint) in the first leg of the authentication process. The OIDC login endpoint should respond with an ID token (JSON web token) containing information about the requesting user that you specified when setting up LTI 1.3
* /redirect is where the ID token is sent to and where the page redirects after logging in to OIDC, here is where the tool is launched. The ID token carries a signature and kid attached to a JSON web key (JWK) on the brightspace JSON web keyset (JWKS) endpoint. The launchTool function verifies the JWT and makes sure all the required information is contained within the token before launching (redirecting to) the tool.
* /example shows a boiler plate proof of concept for the tool that takes information in the ID token, formats, and presents it to the user.
* /.well-known/jwks contains a public JWKS that the client generates (rather than the platform) which is used to build, sign, and verify JWTs used to access LTI 1.3 scopes The JWKS endpoint contains a key for each LTI 1.3 tool.
   

**Note:**

This code runs on AWS Lambda using the [Serverless Framework](https://www.serverless.com/framework/docs/providers/aws/guide/quick-start/). To use Serverless, you will need to set up your environment including a serverless.yml file (link to quickstart above).

You may download and modify this code however you see fit.
