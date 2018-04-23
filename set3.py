import random
from random import _urandom
from crypto import *
from Crypto.Cipher import AES

#17
aes = AES.new(_urandom(16))
def get_cbc_ciphertext():
    pt = random.choice([b64decode(b.strip()) for b in '''MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'''.split('\n')])
    iv = _urandom(aes.block_size)
    return iv, aes_cbc_encrypt(aes, iv, pkcs7_pad(pt, aes.block_size))

def padding_oracle(iv, ct):
    padded_pt = aes_cbc_decrypt(aes, iv, ct)
    padding_size = padded_pt[-1]
    return padded_pt[-padding_size:] == bytes([padding_size] * padding_size)

iv, ct = get_cbc_ciphertext()
print(cbc_padding_oracle_attack(padding_oracle, iv, ct, aes.block_size))
