"use strict";
exports.__esModule = true;
var test = process.argv[0] == 'test' ? true : false;
exports.bitcoin = test ? {
    messagePrefix: '\x18TestPocketnet Signed Message :\n',
    bech32: 'tb',
    bip32: {
        public: 0x043587cf,
        private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef
} : {
    messagePrefix: '\x18Pocketnet Signed Message:\n',
    bech32: 'bc',
    bip32: {
        public: 0x043587cf,
        private: 0x04358394
    },
    pubKeyHash: 0x37,
    scriptHash: 0x50,
    wif: 0x21
};
/*
const testnet: Network = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'tb',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef
};*/
