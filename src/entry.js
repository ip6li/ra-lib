import {ConfigToolbox} from "./crypt.config";
import createPKCS10 from "./crypt.csr";
import createPKCS12 from "./crypt.pkcs12";


class X509 {
    constructor(name, doRestoreConfig=false) {
        this.configToolbox = ConfigToolbox.getInstanceOf(name, doRestoreConfig);
        this.getConfig = function () { return this.configToolbox; };
        this.setConfig = function (newConfig) { this.configToolbox.setConfig(newConfig); };

        const defaultRequest = {
            method: 'POST', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'omit', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/json'
            },
            redirect: 'follow', // manual, *follow, error
            referrer: 'no-referrer', // no-referrer, *client
            body: JSON.stringify({}) // body data type must match "Content-Type" header
        };

        this.config = this.configToolbox.getConfig();
        this.config.defaultRequest = defaultRequest;
        this.configToolbox.setConfig(this.config);
    }

    createPKCS10(subject, modulus) {
        return createPKCS10(this.getConfig(), subject, modulus);
    }

    createPKCS12(keyStore, password, friendlyName = "Powered by IP6LI") {
        return createPKCS12(keyStore, password, friendlyName);
    }

    loadConfig(configURL, request=this.config.defaultRequest) {
        return fetch(configURL, request).then((response)=>{
            return response.json().then((data)=>{
                this.setConfig(data.config);
            });
        });
    }

}


export default {
    X509
};
