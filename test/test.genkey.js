const assert = chai.assert;
const x509 = new MyX509("X509sessions", false);

describe('Crypto', function () {
    const refKeyPairRSA = {};
    // private key and certificate for tests for reference
    // created by OpenSSL
    refKeyPairRSA.privateKey = `-----BEGIN PRIVATE KEY-----
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
wSUT0pZ9teX/A9FBdVZR3yn1KBWVnGJp
-----END PRIVATE KEY-----`;

    refKeyPairRSA.certificate = `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIUA+kAup0l35VwaRdO+63tVSChlMkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJdGVzdC1jZXJ0MB4XDTE5MTIwNjA4NTcyNVoXDTI5MTIw
MzA4NTcyNVowFDESMBAGA1UEAwwJdGVzdC1jZXJ0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEA7GqsvMkXjiqnk/wocR/sMuvf5odJ5+i+KyF/5nn5q6tG
QJcDvhJJiOd/H5jVeC74QiTk3CDoNwKUuVukvkCpFkW5PDJ3VGTHLb6FrGN3pb7q
YcVRRoUvvPeBLcxGQXsL3+dacR9Gc9+h5JZ1H7uMmEgI2v1bwgNw9LXvZ3IpEe9g
mTRyqrpIzGLvsprMWWpr2nnyhrhSGoyzkM5dpspE8g7z9zTry52GBxHARz3SxEW9
5bR7qwt/TXEgd1ycKpPZWyeUUJDbRxmiqNM3uHmogSG9kBwfu4bCj1KmBO2wN88N
Dw2gmEdOQvFVkmltGbdBvDNfV0Q81bNFlFWwBvmdDRuxXyn/jWU2/tflJgY8imdR
EPmVJAVUYO2lsLkJJW92Tv74Z/7CKDwAG81MKPPgLa8GjtaLI9FSYMzmoFA0bmMK
GUyQcfnwJXjmQkd9Ku7C2JCh+IwSBzIdXY2l517nfrIwdc3S8IX76BK/RJM7mL9D
/ELQfxnUsHJJ3Q6eQ/gP/lnDRnup1nNen6etHjynZA3AVFI5yqoBKaGgxHS7VMP3
qoCMJrQkjhvzV5TTHAZj3NbIQPltM9e5NVPIKbw+1z1TYOlxwMJk7oCTOQ7xVz0k
a1+AUj4ciOsD75CjhGh0Jnrle+Nvm1YIyfVa36EOscSFf0Ro/GMhTVnmycXrZSkC
AwEAAaNmMGQwFAYDVR0RBA0wC4IJdGVzdC1jZXJ0MB0GA1UdDgQWBBTc8yN+eUo4
Cvc6VuquijenhDpYuDAfBgNVHSMEGDAWgBTc8yN+eUo4Cvc6VuquijenhDpYuDAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBE4aCg5dRQ21YYGf/ci6pD
KHlsdueo7hgMX011jgA/ySYez0eIB9nfPXs/RLvnieA4KuJXPjSSmlfc3kWv3qw5
NQhIJEPRkTGE2wSYJ2i9VDgROGhSQALZYV3QaJ1w9D+W4iZSqXq+m0PN9A0tPpwl
SrrARh3OCsadsW6ihWiffi4sUjsPNkAJskMJWiPPRhGJL3KZfxdvncFZdpMkRQsS
BAIOlLhIzTNj8XxttA4BLgRSVBqdJvojK2F8EPTbPSdEKA1jfiCN5FRpC7TerQCt
m6X+/G74WaOMFXn+HTdUigLSFGmJZqwdlYRRg70kB5GJQnfSPqp5jkmmV7Af237H
s9EARc5PZ6mTApJamcnBeqmVSaz8i2kLKoTSL4119WufG8RcYr2MH7lOupdqYAY9
CdCpIPyGl03ML5uNgF85TeBFoy26guK0bIrQrH2PZTmnlC2DLt4DF7RmkySL5KiU
kSH8CZrpkLqWPgZzPtQ+UZbDRkwwRcvJfaHaMt/Z/6rT4q91p0RDSFRVepz9Vt3h
K7M9qCFhhzz8jMbI1CzbKicNcJycf1mQfMfj8TYtuOMzXb/dCjznYgqWpJRSdg5J
fT6QylzRb2rQTvSen2GhBWW9844M76XXGQAPMbMCWWNk/+eNmPqV9oWJivpKt6vU
gDy3iU6RHfWM8mw7JKO8WA==
-----END CERTIFICATE-----`;

    describe('TextEncoder class must resolve, because browser must support it', () => {
        it('should return a Promise resolve', async () => {
            const plainText = "Hello world!\nUmlaute: äöüÄÖÜß€";
            let sequence = Promise.resolve();
            sequence = sequence.then(() => {
                const uint8array = new TextEncoder("utf-8").encode(plainText);
                const result = new TextDecoder().decode(uint8array);
                if (plainText === result) {
                    return Promise.resolve("result is equal to plainText");
                } else {
                    return Promise.reject("result is not equal to plainText");
                }
            });

            return await sequence;
        });
    });

    describe('Create PKCS#10 Certificate Signing Request', async () => {
        it('should return a Promise resolve when CSR generation is successful', async () => {
            const div_pkey = document.getElementById("div_pkey");
            const div_csr = document.getElementById("div_csr");
            const subject = [
                {
                    name: 'commonName',
                    value: 'example.org'
                },
                {
                    name: 'countryName',
                    value: 'DE'
                },
                {
                    name: 'localityName',
                    value: 'Taunusstein'
                },
                {
                    name: 'organizationName',
                    value: 'CAcert'
                }
            ];
            return await x509.createPKCS10(subject, 2048).then((result)=>{
                div_pkey.innerText = result.privateKey;
                div_csr.innerText = result.csr;
                const config = x509.getConfig().config;
                x509.setConfig(config);
                return result;
            });
        }).timeout(20000).slow(15000);
    });

    describe('Create PKCS#12', () => {
        it('PKCS#12 file', async () => {
            const pkcs12password = "geheim";
            const configToolbox = x509.getConfig();
            const config = configToolbox.config;
            const keyStore = config.keystore;
            keyStore.privateKey = refKeyPairRSA.privateKey;
            keyStore.certificate = refKeyPairRSA.certificate;
            return await x509.createPKCS12(keyStore, pkcs12password).then((p12b64)=>{
                console.log(typeof p12b64);
                const a = document.createElement('a');
                a.download = 'certificate.p12';
                a.setAttribute('href', 'data:application/x-pkcs12;base64,' + p12b64);
                a.appendChild(document.createTextNode('Download'));
                a.click();
            });
        }).timeout(10000).slow(5000);
    });

});
