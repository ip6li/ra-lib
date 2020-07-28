import forge from "forge";

export default function createPKCS10(configToolbox, subject, modulus, attributes) {

    let sequence = Promise.resolve();

    sequence = sequence.then(()=> {
        const config = configToolbox.getConfig();
        const keys = forge.pki.rsa.generateKeyPair(modulus);
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;
        csr.setSubject(subject);
        if (typeof attributes !== "undefined") {
            csr.setAttributes(attributes);
        }
        csr.sign(keys.privateKey, forge.md.sha256.create());

        config.keystore.privateKey = forge.pki.privateKeyToPem(keys.privateKey);
        config.keystore.publicKey = forge.pki.publicKeyToPem(keys.publicKey);
        config.keystore.csr = forge.pki.certificationRequestToPem(csr);
        configToolbox.setConfig(config);

        return config.keystore;
    });

    return sequence.then((result)=>{
        return result;
    });
}
