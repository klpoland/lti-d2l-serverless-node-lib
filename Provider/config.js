module.exports.config = () => {
    const config = {
        clientId: 'd2l_oauth2_client_id',
        clientSecret: 'd2l_oauth2_client_secret',
        hostUrl: 'https://your.platform.url',
        accessTokenUrl: 'https://auth.brightspace.com/core/connect/token',
        clientUrl: 'https://your.host'
    }
    return config
}
