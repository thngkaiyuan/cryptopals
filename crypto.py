from base64 import b64encode, b64decode
from ngram_score import ngram_score
from itertools import combinations
from Crypto.Util.number import bytes_to_long, long_to_bytes

monogram = ngram_score('english_monograms.txt')
quadgram = ngram_score('english_quadgrams.txt')

def hex_to_b64(hex_str):
    return b64encode(bytes.fromhex(hex_str)).decode()

def xor_bytes(bytes1, bytes2):
    return bytes([x ^ y for x, y in zip(bytes1, bytes2)])
    
def xor_byte(bytes, byte):
    return xor_bytes(bytes, [byte for _ in range(len(bytes))])

def rep_xor(bytes, rep_key):
    key = rep_key * -(-len(bytes)//len(rep_key)) # ceiling div
    return xor_bytes(bytes, key)

def get_top_n(texts, n=5, enum=False, use_monogram=False):
    global monogram, quadgram
    ngram = monogram if use_monogram else quadgram
    return sorted([(ngram.score(text), text, i) if enum else (ngram.score(text), text) for i, text in enumerate(texts)], reverse = True)[:n]

''' For equal length bytes '''
def hamming_dist(bytes1, bytes2):
    assert len(bytes1) == len(bytes2)
    xor = bytes_to_long(bytes1) ^ bytes_to_long(bytes2)
    dist = 0
    while xor != 0:
        dist += 1
        xor &= xor - 1
    return dist

def gen_hamming_dist(bytes1, bytes2):
    def right_pad(bytes, padding, size):
        return bytes + (size - len(bytes)) * padding
    size = max(len(bytes1), len(bytes2))
    return hamming_dist(right_pad(bytes1, b'\x00', size), right_pad(bytes2, b'\x00', size))

def chop(seq, block_size):
    return [seq[i:i+block_size] for i in range(0, len(seq), block_size)]

''' AKA Vigenere Cipher '''
def guess_rep_xor_key_size(c, low, high):
    min_hd, ks = None, None
    for keysize in range(low, high):
        hds = [hamming_dist(blk1, blk2)/keysize for blk1, blk2 in combinations(chop(c, keysize)[:4], 2)]
        hd = sum(hds)/len(hds)
        if not min_hd or hd < min_hd:
            min_hd = hd
            ks = keysize
    return ks

def has_repeated_blocks(c, blocksize):
    blks = chop(c, blocksize)        
    for i in range(len(blks)):
        for j in range(i+1, len(blks)):
            if blks[i] == blks[j]:
                return True
    return False