# Browser Javascript X.509 Toolbox

This library provides following functions:

* Create RSA key pair
* PKCS#10 certificate signing request
* encrypt and decrypt arbitrary messages with X.509 certificates/private key
* sign und verify arbitrary messages with X.509 certificates/private key

# Theory Of Operation

Recommended procedure for usage:

1. Browser creates key pair and a PKCS#10 signing request.
1. Browser request certificate from authentication server. This connections must be be trusted, because certificate must be authentic.
1. Signing request is sent to this authentication server. This connections must be be trusted, because user/password be be also sent to authenticate signing request.
1. Server signs PKCS#10 and replies with signed certificate for client.
1. Now Browser can connect to other servers even through insecure connections. Every request is signed with private key end encrypted with certificate provided by authentication server.
1. Server signs replies with ist own private key and encrypts message with browsers certificate with is always provided by CMS signed messages.  

Following data needs to be stored in browsers session store:

* Private Key
* Signed Certificate from PKCS#10 request
* Servers certificate

# Use Cases

* Real End2End encryption, between browser and application.
* Distributed Authentication, even for micro services
* Complicates DoS attacks a little bit, due to signing/encryption (takes some milliseconds of cpu power)

# Security Considerations

It is strongly recommended to split

* config
* authentication
* application

to different servers and - better - to different hosting centers.

## Config Server

This server has to provide a htlm snippet which provides

* html code (e.g. a simple login page)
* this Javascript library (bundle.js)
* Encryption certificate
* CA certificate
* A json file with configuration (where to find authentication and application server)

This server needs to provide static content only. No Java, PHP or whatever. There are no credentials,
no private keys or whatever which maybe can be stolen.

## Authentication Server

This server has to decrypt the first packet from that library. Tasks:

* decrypt CMS message with credentials and PKCS#10 certificate signing request
* verify users credentials
* in case credentials are ok, sign PKCS#10
* reply with signed certificate

To make your life easier, you can use a ready to run PKI solution e.g. EJBCA. Webservice
ca be used to validate user and sign PKCS#10 request.

This authentication server should not do other things than authentication. It contains
users credentials and private keys. In case this server is compromised, you will
be in trouble.

## Application Server

Your application server must

* decrypt and 
* verify 

every request from client. This will ensure that request was sent from authenticated user.
Any type of authorization must be done on server side. In case you want to store state data
in users browser consider to encrypt it with encryption certificate mentioned in section
*config server* due to the fact that your application server has libraries to
encrypt/decrypt CMS messages and the private key needed for decryption.

Turn off session cookies, you will not need them. Users certificate is the session ID. 

# Security Issues

Users private key is stored locally and will never leave its storage. Same
is true for server side. So you can forget insecure session ids,
cross site request forgery and other things which may 
compromise shared secrets. Every request and reply is signed with matching
private key and may be considered as authentic.

But you may consider that security of your application depends on following items:

* Web browsers security regarding *session storage*. For reference see *sessionStorage* https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API
* Your authentication server: Before delivering to production consider to do a thorough penetration test.
Order pentester to try to get private key or users credentials by all available means.
* Update your servers at least on a weekly basis. Most hacks are successful due to unpatched
security holes.
* Your application server may contain valuable data. This library mitigates problems
with sessions ids, CSRF and so on, but it does not help regarding injection and
architectural flaws. So updates and penetration tests are also a *must have* on
your application servers.
* This library kills web application firewalls because it encrypts traffic on
layer 7. A WAF has no chance to see what client sends to server. This plus
on privacy may be considered as a drawback. But it is not - think twice - if you think
you need a WAF, your application is insecure. Best WAF is a secure application
(security by design)  

# How To Use

See directory test, it shows how to use this library.

* genkey.html is a html test
* test.genkey.js is a Mocha test script
* example.class.js shows how to derive a subclass, it is used by test.genkey.js 

