const express = require('express');
const app = express();
const uuidv4 = require('uuid/v4');
const nJwt = require('njwt');
const config = require('./config');

// TODO: Retrieve signing key from a data store
const secureRandom = require('secure-random');
const b64string = config.web.base64SigningKey;
const signingKey = Buffer.from(b64string, 'base64') || secureRandom(256, {type: 'Buffer'});   // Create a highly random byte array of 256 bytes
//console.log(signingKey);
//const base64SigningKey = signingKey.toString('base64');
//console.log(base64SigningKey);

const hostname = '127.0.0.1';
const port = config.web.appPort;

let responseStatus = 404;
let responseBody = {'error':{'code':responseStatus,'message':'Not Found'}};

app.use(function (req, res, next) {
    res.setHeader('Content-Type', 'application/json');
    let requestId = uuidv4();
    res.setHeader('X-njwtsample-Request-Id', requestId);
    // HTTP-only cookies aren't accessible via JavaScript through the Document.cookie property.
    res.setHeader('Set-Cookie',`njwtsample-Request-Id=${requestId}; HttpOnly`);   // Non-production
    // A secure cookie will only be sent to the server when a request is made using SSL and the HTTPS protocol.
    //res.setHeader('Set-Cookie',`njwtsample-Request-Id=${requestId}; Secure; HttpOnly`); // TODO: Production
    console.log(`${Date.now()}\t${req.method}\t${req.url}\t${req.header('authorization')}`);
    next();
  });

app.get(['/api','/api/v(1.0|1)'], function (req, res) {
    //console.log(req.headers['authorization']);
    if (!req.headers['authorization']) {
        responseStatus = 401;
        responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
    } else {
        try {
            //console.log(req.headers['authorization']);
            let token = req.headers['authorization'].slice(7);
            //console.log(token);
            let verifiedJwt = nJwt.verify(token,signingKey);
            responseStatus = 200;
            responseBody = {'data':null};        
        } catch(error) {
            responseStatus = 401;
            responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
            console.log(error);
        }
    }

    res.statusCode = responseStatus;
    res.write(JSON.stringify(responseBody));
    res.send();
});

app.post(['/api/login','/api/v(1.0|1)/login'], function(req, res) {
    let jsonString = '';
    if(req.headers['content-type'] === 'application/json') {
        req.on('data', function(data) {
            jsonString += data;
            if (jsonString.length > 1e6) {
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

            if (!user.authenticated) {
                responseStatus = 401;
                responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
            } else {
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
                    responseStatus = 200;
                    responseBody = {'data':null};
                } catch (error) {
                    responseStatus = 401;
                    responseBody = {'error':{'code':responseStatus,'message':'Unauthorized'}};
                    console.log(error);
                } finally {
                    res.statusCode = responseStatus;
                    res.write(JSON.stringify(responseBody));
                    res.send();
                }
            }
        });
    } else {
        responseStatus = 405;
        responseBody = {'error':{'code':responseStatus,'message':'Method Not Allowed'}};
        res.statusCode = responseStatus;
        res.write(JSON.stringify(responseBody));
        res.send();
    }
});

app.listen(port, function () {
  console.log(`Server running at http://${hostname}:${port}/`);
  console.log('Time\tMethod\tURL\tAuthorization');
});