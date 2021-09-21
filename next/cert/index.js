const
    {readFileSync}   = require('fs'),
    {join: joinPath} = require('path'),
    load             = (filename) => readFileSync(joinPath(__dirname, filename));

exports.client = {
    private: load('client.key'),
    public:  load('client.key.pub')
};

exports.client_tls = {
    private: load('client_tls.key'),
    public:  load('client_tls.key.pub')
};
