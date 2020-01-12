import forge from "forge";

export default function createPKCS12(keyStore, password, friendlyName) {
    let sequence = Promise.resolve();

    sequence = sequence.then(()=> {
        const newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
            keyStore.privateKey, [keyStore.certificate], password,
            {generateLocalKeyId: true, friendlyName: friendlyName});
        return forge.asn1.toDer(newPkcs12Asn1).getBytes();
    });

    return sequence.then((result)=>{
        return result;
    })
}
