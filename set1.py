from crypto import *
from itertools import zip_longest
from Crypto.Cipher import AES

#1
print(hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

#2
print(xor_bytes(bytes.fromhex('1c0111001f010100061a024b53535009181c'), bytes.fromhex('686974207468652062756c6c277320657965')).hex())

#3
print(get_top_n([xor_byte(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'), i).decode('latin-1') for i in range(256)], 1))

#4
with open('4.txt','r') as f:
    s = f.readlines()
texts = []
for hex_str in s:
    for i in range(256):
        texts.append(xor_byte(bytes.fromhex(hex_str.strip()), i).decode('latin-1'))
print(get_top_n(texts, 1))

#5
print(rep_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b"ICE").hex())

#6
with open('6.txt') as f:
    c = b64decode(f.read().replace('\n', ''))
ks = guess_rep_xor_key_size(c, 2, 42)
blks = list(zip_longest(*chop(c, ks)))
blks = [bytes(filter(None, blk)) for blk in blks]
key = ''
for blk in blks:
    texts = [xor_byte(blk, i).decode('latin-1') for i in range(256)]
    _, _, k = get_top_n(texts, n=1, enum=True)[0]
    key += chr(k)
print(key)
print(rep_xor(c, bytes(key, 'latin-1')))

#7
with open('7.txt') as f:
    c = b64decode(f.read().replace('\n', ''))
aes = AES.new('YELLOW SUBMARINE')
print(aes.decrypt(c))

#8
with open('8.txt') as f:
    cts = [bytes.fromhex(line.strip()) for line in f.readlines()]
for ct in cts:
    if has_repeated_blocks(ct, 16):
        print(ct.hex())
        break
