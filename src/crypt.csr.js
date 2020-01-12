import forge from "forge";

export default function createPKCS10(configToolbox, subject, modulus) {
    const config = configToolbox.getConfig();
    const keys = forge.pki.rsa.generateKeyPair(modulus);
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject(subject);
    csr.sign(keys.privateKey);

    config.keystore.privateKey = forge.pki.privateKeyToPem(keys.privateKey);
    config.keystore.publicKey = forge.pki.publicKeyToPem(keys.publicKey);
    config.keystore.csr = forge.pki.certificationRequestToPem(csr);
    configToolbox.setConfig(config);

    return config.keystore;
}
