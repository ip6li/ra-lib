import forge from "forge";

export default function createPKCS12(configToolbox, password, friendlyName) {
    const config = configToolbox.getConfig();
    const keyStore = config.keyStore;
    const newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
        keyStore.privateKey, [keyStore.certificate], password,
        {generateLocalKeyId: true, friendlyName: friendlyName});
    return  forge.asn1.toDer(newPkcs12Asn1).getBytes();
}
