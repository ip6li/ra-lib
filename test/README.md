# Test Webserver

There is is test server which provides a very simple PKI backend for
this library.

## Prepare

To prepare test execute

    npm run build

## Do Test

Start test web server with

    ./test-webserver.py

It opens port 8000 on all available interfaces at localhost.
Open url http://127.0.0.1:8000 to start tests. Browser will show
Mocha test results. For details see console.log output in
browsers debug window.

## Reference Implementation

Test web server is a Python3 script which uses OpenSSL cli as backend.
OpenSSL commands explains best how to create and sign certificates
for that library.

## Other Functions

Test web server offers some other, not yet activated function.
Do not enable them, because they are for future developments.

# Create self signed RSA-PSS certificate

    openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out key.pem
    openssl req -new -x509 -days 999999 -sha256 -key key.pem -out crt.pem -subj '/CN=Test RSAPSS'

## Options

    curl --verbose -X OPTIONS http://127.0.0.1:3000/config.json; echo

# MacOS

## Install m2crypto

    env LDFLAGS="-L$(brew --prefix openssl)/lib" CFLAGS="-I$(brew --prefix openssl)/include" SWIG_FEATURES="-cpperraswarn -includeall -I$(brew --prefix openssl)/include" pip3 install m2crypto

## Install pyopenssl

    env LDFLAGS="-L$(brew --prefix openssl)/lib" CFLAGS="-I$(brew --prefix openssl)/include" pip3 install pyopenssl

