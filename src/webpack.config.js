path = require('path'),
module.exports = {
    mode: "development",
    module: {
        rules: [
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
            }
        ]
    },
    entry: './entry.js',
    output: {
        path: __dirname + '/dist',
        publicPath: '/',
        filename: 'bundle.js',
        library: 'cfcrypt',
        libraryTarget: 'window',
        libraryExport: 'default'
    },
};
