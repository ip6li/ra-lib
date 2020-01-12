
class ConfigToolbox {

    constructor(name, doRestoreConfig) {
        this.storageName = name;
        this.doRestoreConfig = doRestoreConfig;
        this.config = {};
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

    saveConfig() {
        if (typeof this.config !== "undefined") {
            sessionStorage.setItem(this.storageName, JSON.stringify(this.config));
        }
    }

    restoreConfig() {
        const storedConfig = sessionStorage.getItem(this.storageName);
        if (typeof storedConfig === "string") {
            const restoredConfig = JSON.parse(storedConfig);
            if (typeof restoredConfig === "object") {
                this.config = restoredConfig;
            }
        }
    }

    setConfig(newConfig) {
        this.config = Object.assign(this.config, newConfig);
        this.saveConfig();
    }

    getConfig() {
        return this.config;
    }

}

export {ConfigToolbox};
