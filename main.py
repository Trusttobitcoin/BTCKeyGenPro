import os
import requests
import hashlib
import binascii
import hmac
import base58
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number, number_to_string
from Cryptodome.Hash import RIPEMD160


def fetch_bip39_wordlist():
    url = 'https://raw.githubusercontent.com/ChristopherA/iambic-mnemonic/master/word-lists/bip39-2048.txt'
    response = requests.get(url)
    return response.text.split('\n')


def generate_entropy(length=32):
    return os.urandom(length)


def generate_mnemonic(entropy, wordlist):
    entropy_hex = binascii.hexlify(entropy).decode('utf8')
    raw_binary = bin(int(entropy_hex, 16))[2:].zfill(len(entropy_hex) * 4)
    checksum = bin(int(hashlib.sha256(binascii.unhexlify(entropy_hex)).hexdigest(), 16))[2:].zfill(256)
    raw_binary += checksum[:len(raw_binary) // 32]
    return ' '.join([wordlist[int(raw_binary[i:i + 11], 2)] for i in range(0, len(raw_binary), 11)])


def generate_seed(mnemonic, passphrase=''):
    mnemonic_bytes = mnemonic.encode('utf-8')
    passphrase_bytes = ('mnemonic' + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, passphrase_bytes, 2048)[:64]


def generate_master_key(seed):
    hash = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return hash[:32], hash[32:]


def private_to_public_key(private_key):
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    return sk.get_verifying_key().to_string()


def compute_child_private_key(parent_private_key, IL):
    IL_num = string_to_number(IL)
    if IL_num >= SECP256k1.order:
        raise ValueError("Invalid IL")
    child_private_key = (string_to_number(parent_private_key) + IL_num) % SECP256k1.order
    return number_to_string(child_private_key, SECP256k1.order)


def generate_child_private_key(parent_private_key, parent_chain_code, index):
    parent_public_key = private_to_public_key(parent_private_key)
    data = parent_public_key + index.to_bytes(4, byteorder='big')
    hash = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    return compute_child_private_key(parent_private_key, hash[:32]), hash[32:]


def hash160(data):
    return RIPEMD160.new(hashlib.sha256(data).digest()).digest()


def generate_address(private_key):
    public_key = private_to_public_key(private_key)
    version = b'\x6f'  # Testnet version byte
    versioned_payload = version + hash160(public_key)
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address_bytes = versioned_payload + checksum
    return base58.b58encode(address_bytes)


if __name__ == "__main__":
    WORDLIST = fetch_bip39_wordlist()
    entropy = generate_entropy()
    mnemonic = generate_mnemonic(entropy, WORDLIST)
    seed = generate_seed(mnemonic)
    master_private_key, chain_code = generate_master_key(seed)

    # Printing the initial results
    print("\nMnemonic:", mnemonic)
    print("Seed:", binascii.hexlify(seed).decode())
    print("Master private key:", binascii.hexlify(master_private_key).decode())
    print("Master chain code:", binascii.hexlify(chain_code).decode())

    while True:
        child_private_key, child_chain_code = generate_child_private_key(master_private_key, chain_code, 0)
        address = generate_address(child_private_key)
        
        # Printing the new address and child keys
        print("\nChild private key:", binascii.hexlify(child_private_key).decode())
        print("Child chain code:", binascii.hexlify(child_chain_code).decode())
        print("Address:", address.decode())

        # Ask the user if they want to generate a new address
        user_input = input("\nDo you want to generate a new address? (y/N): ").strip().lower()
        if user_input != 'y':
            print("Exiting the program.")
            break
