# BTCKeyGenPro

A toolset for Bitcoin, providing streamlined generation of key Bitcoin components: from raw entropy to Testnet addresses.

## Features
- Generate secure entropy.
- Convert entropy into a BIP39 mnemonic phrase.
- Produce a cryptographic seed from mnemonics.
- Derive master and child private/public keys and chain codes.
- Create Bitcoin Testnet addresses from child private keys.

## How to Use

1. Clone this repo:
git clone https://github.com/YourUsername/BTCKeyGenPro.git


2. Change directory:
cd BTCKeyGenPro


3. Install required libraries:
pip install -r requirements.txt


4. Run the script:
python3 main.py


## Dependencies
- Python 3.6+
- Libraries: `requests`, `ecdsa`, `base58`, `pycryptodomex`

## License
Distributed under the MIT License. See `LICENSE` for more info.
