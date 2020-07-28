class MyX509 extends window.cfcrypt.X509 {

    constructor(name, doRestoreConfig) {
        super(name, doRestoreConfig);
    }

    loadConfig(configURL) {
        return super.loadConfig(configURL);
    }

    createPKCS10(subject, modulus, attributes) {
        return super.createPKCS10(subject, modulus, attributes);
    }

    createPKCS12(keyStroe, password) {
        return super.createPKCS12(keyStroe, password);
    }
}


window.cfcrypt.MyX509 = MyX509;
