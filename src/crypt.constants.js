import * as asn1js from "asn1js";

export const sessionName = "X509sessions";

export const csrBegin = "-----BEGIN CERTIFICATE REQUEST-----";
export const csrEnd = "-----END CERTIFICATE REQUEST-----";
export const certBegin = "-----BEGIN CERTIFICATE-----";
export const certEnd = "-----END CERTIFICATE-----";
export const cmsBegin = "-----BEGIN CMS-----";
export const cmsEnd = "-----END CMS-----";

export const privateKeyDelimiter = /(-----(BEGIN|END)( EC)?( NEW)? PRIVATE KEY-----|\n)/g;
export const certificateDelimiter = /(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g;
export const publicKeyDelimiter = /(-----(BEGIN|END)( NEW)? PUBLIC KEY-----|\n)/g;
export const cmsDelimiter = /(-----(BEGIN|END)( NEW)? CMS-----|\n)/g;


export const pkcs_9_at_extensionRequest = "1.2.840.113549.1.9.14";
export const extnID = "2.5.29.14";
export const sanID = "2.5.29.17";
export const envelopedDataID = "1.2.840.113549.1.7.3";
export const contentTypeDataID = "1.2.840.113549.1.7.1";
export const contentTypesignedDataID = "1.2.840.113549.1.7.2";
export const pkcs7ID = "1.2.840.113549.1.7.1";
export const pkcs9ID = "1.2.840.113549.1.9.3";
export const signingTimeID = "1.2.840.113549.1.9.5";
export const messageDigestID = "1.2.840.113549.1.9.4";
export const dgtIDsha1 = "1.3.14.3.2.26";
export const dgtIDsha256 = "2.16.840.1.101.3.4.2.1";
export const sha1withRSAid = "1.2.840.113549.1.1.5";

// see http://www.umich.edu/~x509/ssleay/asn1-oids.html
export const oid = {
    cn: {type: "2.5.4.3", asn1type: asn1js.Utf8String},
    sn: {type: "2.5.4.4", asn1type: asn1js.Utf8String},
    c: {type: "2.5.4.6", asn1type: asn1js.PrintableString},
    l: {type: "2.5.4.7", asn1type: asn1js.Utf8String},
    st: {type: "2.5.4.8", asn1type: asn1js.Utf8String},
    street: {type: "2.5.4.9", asn1type: asn1js.Utf8String},
    o: {type: "2.5.4.10", asn1type: asn1js.Utf8String},
    ou: {type: "2.5.4.11", asn1type: asn1js.Utf8String},
    t: {type: "2.5.4.12", asn1type: asn1js.Utf8String},
    gn: {type: "2.5.4.42", asn1type: asn1js.Utf8String},
    i: {type: "2.5.4.43", asn1type: asn1js.Utf8String},
    e: {type: "1.2.840.113549.1.9.1", asn1type: asn1js.PrintableString}
};


export const rdnmap = {
    "2.5.4.6": "C",
    "2.5.4.10": "OU",
    "2.5.4.11": "O",
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "S",
    "2.5.4.12": "T",
    "2.5.4.42": "GN",
    "2.5.4.43": "I",
    "2.5.4.4": "SN",
    "1.2.840.113549.1.9.1": "E-mail"
};


// https://tools.ietf.org/html/rfc2459
export const oidAltNames = {
    otherName: {type: 0, asn1type: asn1js.Utf8String},
    rfc822Name: {type: 1, asn1type: asn1js.Utf8String},
    dNSName: {type: 2, asn1type: asn1js.Utf8String},
    x400Address: {type: 3, asn1type: asn1js.Utf8String},
    directoryName: {type: 4, asn1type: asn1js.Utf8String},
    ediPartyName: {type: 5, asn1type: asn1js.Utf8String},
    uniformResourceIdentifier: {type: 6, asn1type: asn1js.Utf8String},
    iPAddress: {type: 7, asn1type: asn1js.Utf8String},
    registeredID: {type: 8, asn1type: asn1js.Utf8String}
};


export const dgstmap = {
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512"
};

export const contypemap = {
    "1.3.6.1.4.1.311.2.1.4": "Authenticode signing information",
    "1.2.840.113549.1.7.1": "Data content"
};


export const algorithmOids = {
    "1.2.840.113549.1.1.11": "SHA-256",
    "1.2.840.113549.1.1.12": "SHA-384",
    "1.2.840.113549.1.1.13": "SHA-512"
};
