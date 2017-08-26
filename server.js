var http = require('http');
const uuidv4 = require('uuid/v4');
var nJwt = require('njwt');
const config = require('./config');

// TODO: Retrieve signing key from a data store
var secureRandom = require('secure-random');
const b64string = config.web.base64SigningKey;
var signingKey = Buffer.from(b64string, 'base64') || secureRandom(256, {type: 'Buffer'});   // Create a highly random byte array of 256 bytes
//console.log(signingKey);
//var base64SigningKey = signingKey.toString('base64');
//console.log(base64SigningKey);

const hostname = '127.0.0.1';
const port = config.web.serverPort;

const server = http.createServer(function (req, res) {

    res.setHeader('Content-Type', 'application/json');
    let requestId = uuidv4();
    res.setHeader('X-njwtsample-Request-Id', requestId);
    // HTTP-only cookies aren't accessible via JavaScript through the Document.cookie property.
    res.setHeader('Set-Cookie',`njwtsample-Request-Id=${requestId}; HttpOnly`);   // Non-production
    // A secure cookie will only be sent to the server when a request is made using SSL and the HTTPS protocol.
    //res.setHeader('Set-Cookie',`njwtsample-Request-Id=${requestId}; Secure; HttpOnly`); // TODO: Production

    let responseStatus = 200;
    let responseBody = {'data':null};
    let jsonString = '';

    if (req.method === 'GET'
        && (
            req.url === '/api/'
            || req.url === '/api/v1.0/'
            || req.url === '/api/v1/'
        )
    ) {
        //console.log(req.headers['authorization']);
        if (!req.headers['authorization'])
            {
                responseStatus = 401;
                responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
                res.statusCode = responseStatus;
                res.write(JSON.stringify(responseBody));
                res.end();
            }
            else {
                try {
                    //console.log(req.headers['authorization']);
                    let token = req.headers['authorization'].slice(7);
                    //console.log(token);
                    let verifiedJwt = nJwt.verify(token,signingKey);
                  }
                catch(error) {
                    responseStatus = 401;
                    responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
                    console.log(error);
                }
                finally {
                    res.statusCode = responseStatus;
                    res.write(JSON.stringify(responseBody));
                    res.end();
                }
            }
    }
    else if (req.method === 'POST'
        && (
            req.url === '/api/login/'
            || req.url === '/api/v1.0/login/'
            || req.url === '/api/v1/login/'
        )
    ) {
        if (req.headers['content-type'] === 'application/json')
            {
                req.on('data', function(data) {
                    jsonString += data;
                    if(jsonString.length > 1e6) {
                        jsonString = {'data':null};
                        responseStatus = 413;
                        responseBody = {'error':{'code':responseStatus,'message':'Payload Too Large'}};
                        req.connection.destroy();
                    }
                });

                req.on('end', function() {
                    let userCredentials = JSON.parse(jsonString);
                    //console.log(userCredentials.userName);

                    // TODO: Authenticate the user credentials
                    let user = {'name':userCredentials.userName,'authenticated':true,'roles':['api']};

                    if(!user.authenticated) {
                        responseStatus = 401;
                        responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
                        res.statusCode = responseStatus;
                        res.write(JSON.stringify(responseBody));
                        res.end();
                    }
                    else {
                        let claims = {
                            iss: `http://${hostname}:${port}/`, // The URL of your service 
                            sub: user.name,      // The UID of the user in your system 
                            scope: user.roles
                        };
                        
                        //console.log(base64SigningKey);

                        try {
                            let jwt = nJwt.create(claims,signingKey);
                            //console.log(jwt);
                            let token = jwt.compact();
                            //console.log(token);
                            let responseAuthorization = `Bearer ${token}`;
                            res.setHeader('Authorization', responseAuthorization);
                            // HTTP-only cookies aren't accessible via JavaScript through the Document.cookie property.
                            res.setHeader('Set-Cookie',`njwtsample-Token=${token}; HttpOnly`);   // Non-production
                            // A secure cookie will only be sent to the server when a request is made using SSL and the HTTPS protocol.
                            //res.setHeader('Set-Cookie',`njwtsample-Token=${token}; Secure; HttpOnly`); // TODO: Production
                        } catch (error) {
                            responseStatus = 401;
                            responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
                            console.log(error);
                        } finally {
                            res.statusCode = responseStatus;
                            res.write(JSON.stringify(responseBody));
                            res.end();
                        }
                    }
                });
            }
            else {
                responseStatus = 405;
                responseBody = {'error':{'code':responseStatus,'message':'Method Not Allowed'}};
                res.statusCode = responseStatus;
                res.write(JSON.stringify(responseBody));
                res.end();
            }
        }
    else{
        responseStatus = 404;
        responseBody = {'error':{'code':responseStatus,'message':'Not Found'}};
        res.statusCode = responseStatus;
        res.write(JSON.stringify(responseBody));
        res.end();
    }
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
  });