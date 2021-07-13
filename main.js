var crypto = require('crypto')

module.exports.requestHooks = [
    function(context) {
        request = context.request;

        var AUTH_TOKEN = request.getEnvironmentVariable("auth_token");
        var AUTH_SECRET = request.getEnvironmentVariable("auth_secret");
        
        var body = request.getBodyText();
        var contentType = body ? request.getHeader('Content-Type') || 'application/json' : null;
        var uri = (request.getUrl() + "").split(/.*(?=\/api)/)[1];
        var method = request.getMethod();
        var timestamp = new Date().toUTCString();

    	// Generate HMAC KEY for Authorization header
        var md5 = body ? crypto.createHash('md5').update(body).digest('base64') : "";
        var canonicalSignature = [method, contentType, md5, uri, timestamp].join();
        var signature = crypto.createHmac('sha256', AUTH_SECRET).update(canonicalSignature).digest('base64');
        var hmacKey = "GLOBO-AUTH-HMAC-SHA256 " + AUTH_TOKEN + ":" + signature;


        request.setHeader('Authorization', hmacKey)
        request.setHeader('Date', timestamp)
        request.setHeader('Content-MD5', md5)
        if(contentType) request.setHeader('Content-Type', contentType)
    },
];