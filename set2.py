from crypto import *
from Crypto.Cipher import AES
from random import randint, _urandom

#9
print(pkcs7_pad(b'YELLOW SUBMARINE', 20))

#10
aes = AES.new('YELLOW SUBMARINE')
with open('10.txt') as f:
    ct = b64decode(f.read().replace('\n', ''))
text = pkcs7_unpad(aes_cbc_decrypt(aes, b'\x00' * aes.block_size, ct))
print(text)
assert ct == aes_cbc_encrypt(aes, b'\x00' * aes.block_size, pkcs7_pad(text, aes.block_size))

#11
def encryption_oracle(_bytes):
    aes = AES.new(_urandom(16))
    plaintext = pkcs7_pad(_urandom(randint(5, 10)) + _bytes + _urandom(randint(5, 10)), aes.block_size)
    if randint(0, 1) == 0: # CBC
        print('Pssss. Using CBC!')
        return aes_cbc_encrypt(aes, _urandom(aes.block_size), plaintext)
    else: # ECB
        print('Pssss. Using ECB!')
        return b''.join([aes.encrypt(blk) for blk in chop(plaintext, aes.block_size)])

print('I sense {} mode being used!'.format(detect_blk_enc_mode(encryption_oracle, 16)))

#12
aes = AES.new(_urandom(16))
def blah(_bytes):
    plaintext = pkcs7_pad(_bytes + bytes(b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')), aes.block_size)
    return b''.join([aes.encrypt(blk) for blk in chop(plaintext, aes.block_size)])
print(ecb_decrypt_appended_bytes(blah))

#13
pass

#14
def make_oracle(prefix, target):
    def oracle(_buf):
        plaintext = pkcs7_pad(prefix + _buf + target, aes.block_size)
        return b''.join([aes.encrypt(blk) for blk in chop(plaintext, aes.block_size)])
    return oracle

for _ in range(20):
    prefix = _urandom(randint(0, 100))
    target = _urandom(randint(0, 100))
    oracle = make_oracle(prefix, target)
    assert target == ecb_decrypt_appended_bytes(oracle), 'Failed for prefix {} and target {}.'.format(prefix.hex(), target.hex())

#15
print(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
def test_invalid_padding(buf):
    try:
        pkcs7_unpad(buf)
        print('Failed to catch invalid padding.')
    except:
        print('Caught invalid padding')
test_invalid_padding(b"ICE ICE BABY\x05\x05\x05\x05")
test_invalid_padding(b"ICE ICE BABY\x01\x02\x03\x04")