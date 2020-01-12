import {getParameters, setParameters} from "./crypto.pemutils";

class ConfigToolbox {

    constructor(name, doRestoreConfig) {
        this.storageName = name;
        this.doRestoreConfig = doRestoreConfig;
        this.config = {};
        this.config.keyAlg = {};
        this.config.keyAlg.hash = "SHA-256";
        this.config.keyAlg.sign = "RSASSA-PKCS1-V1_5";
        this.config.keyAlg.modulusLength = 2048;
        this.config.encAlg = {};
        this.config.encAlg.name = "AES-CBC";
        this.config.encAlg.length = 256;
        this.config.keystore = {};

        if (doRestoreConfig) {
            this.restoreConfig();
        }
    }

    static getInstanceOf(name, doRestoreConfig = true) {
        return new ConfigToolbox(name, doRestoreConfig);
    }

    getDoRestoreConfiguration() {
        return this.doRestoreConfig;
    }

    setPemutilsPrms() {
        const prmSet = getParameters();
        prmSet.name = this.config.keyAlg.sign;
        prmSet.hash.name = this.config.keyAlg.hash;
        prmSet.modulusLength = this.config.keyAlg.modulusLength;
        setParameters(prmSet);
    }

    saveConfig() {
        if (typeof this.config !== "undefined") {
            this.setPemutilsPrms();
            sessionStorage.setItem(this.storageName, JSON.stringify(this.config));
        }
    }

    restoreConfig() {
        const storedConfig = sessionStorage.getItem(this.storageName);
        if (typeof storedConfig === "string") {
            const restoredConfig = JSON.parse(storedConfig);
            if (typeof restoredConfig === "object") {
                this.config = restoredConfig;
                this.setPemutilsPrms();
            }
        }
    }

    setEncAlgName(newName) {
        const allowedNames = [ "AES-CBC" ];
        if (allowedNames.includes(newName)) {
            this.config.encAlg.name = newName;
            return true;
        }

        return false;
    }

    setEncAlgLength(newLength) {
        const allowedLength = [ 128, 256 ];
        if (allowedLength.includes(newLength)) {
            this.config.encAlg.length = newLength;
            return true;
        }

        return false;
    }

    setKeyAlgHash(newHash) {
        const allowedHash = [ "SHA-256", "SHA-384", "SHA-512" ];
        if (allowedHash.includes(newHash)) {
            this.config.keyAlg.hash = newHash;
            return true;
        }

        return false;
    }

    setKeyAlgSign(newSign) {
        const allowedSign = [ "RSASSA-PKCS1-V1_5", "RSA-PSS", "ECDSA" ];
        if (allowedSign.includes(newSign)) {
            this.config.keyAlg.sign = newSign;
            return true;
        }

        return false;
    }

    setModulus(newModulus) {
        const intNewModulus = parseInt(newModulus);
        const allowedModulus = [ 2048, 3072, 4096, 8192 ];
        if (allowedModulus.includes(intNewModulus)) {
            this.config.keyAlg.modulusLength = intNewModulus;
            return true;
        }

        return false;
    }

    setConfig(newConfig) {
        this.config = Object.assign(this.config, newConfig);
        this.saveConfig();
    }

    getConfig() {
        return this.config;
    }

    setConfigKey(k, v) {
        this.config[k] = v;
        this.saveConfig();
    }

    getConfigKey(k) {
        return this.config[k];
    }

    setPrivateKey(privateKey) {
        this.config.keystore.privateKey = privateKey;
    }

    getPrivateKey() {
        return this.config.keystore.privateKey;
    }

    setPublicKey(publicKey) {
        this.config.keystore.publicKey = publicKey;
    }

    getPublicKey() {
        return this.config.keystore.publicKey;
    }

    setCsr(csr) {
        this.config.keystore.csr = csr;
    }

    getCsr() {
        return this.config.keystore.csr;
    }

    setCertificate(crt) {
        this.config.keystore.certificate = crt;
    }

    getCertificate() {
        return this.config.keystore.certificate;
    }

    setCAcertificate(crt) {
        this.config.keystore.caCertificate = crt;
    }

    getCAcertificate() {
        return this.config.keystore.caCertificate;
    }

    setRemoteCertificate(crt) {
        this.config.keystore.remoteCertificate = crt;
    }

    getRemoteCertificate() {
        return this.config.keystore.remoteCertificate;
    }
}

export {ConfigToolbox};
