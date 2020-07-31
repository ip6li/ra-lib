import forge from "forge";
import util from 'util';

export default function createPKCS10(configToolbox, subject, modulus, attributes) {
    const config = configToolbox.getConfig();
    let sequence = Promise.resolve();

    sequence = sequence.then(()=> {
        return forge.pki.rsa.generateKeyPair({bits: modulus, workers: -1}, function(err, keys) {
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
        });
    });

    return sequence.then(()=>{
        return config.keystore;
    });
}
