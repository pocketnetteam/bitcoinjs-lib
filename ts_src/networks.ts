// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731
export interface Network {
  messagePrefix: string;
  bech32: string;
  bip32: Bip32;
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
}

interface Bip32 {
  public: number;
  private: number;
}

// @ts-ignore
export const bitcoin: Network = (typeof process !== 'undefined' && process.argv && process.argv.includes && process.argv.includes('--test')) || (typeof window !== 'undefined' && window.testpocketnet)
  ? {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 0x41,
    scriptHash: 0x4e,
    wif: 0x1e,
  } : {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 0x37,
    scriptHash: 0x50,
    wif: 0x21,
  }
  
  
  
  /*{
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 0x41,
    scriptHash: 0x4e,
    wif: 0x1e,
  }*/
