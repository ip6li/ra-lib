import forge from "forge";

export default function createPKCS12(keyStore, password, friendlyName) {
    const privateKey = forge.pki.privateKeyFromPem(keyStore.privateKey);
    const certificates = Array();

    if (typeof keyStore.certificate === "string") {
        certificates.push(forge.pki.certificateFromPem(keyStore.certificate));
    } else {
        keyStore.certificate.forEach((cert)=>{
           certificates.push(forge.pki.certificateFromPem(cert));
        });
    }
    let sequence = Promise.resolve();

    sequence = sequence.then(()=> {
        const newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
            privateKey,
            certificates,
            password,
            {
                generateLocalKeyId: true,
                friendlyName: friendlyName,
                algorithm: "3des"
            });
        return forge.asn1.toDer(newPkcs12Asn1).getBytes();
    });

    return sequence.then((p12Der)=>{
        return forge.util.encode64(p12Der);
    })
}
