from base64 import b64encode, b64decode
from ngram_score import ngram_score
from itertools import combinations
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES

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

def pkcs7_pad(_bytes, blocksize):
    padding_size = blocksize - (len(_bytes) % blocksize)
    return _bytes + bytes([padding_size] * padding_size)

def pkcs7_unpad(_bytes):
    padding_size = _bytes[-1]
    assert _bytes[-padding_size:] == bytes([padding_size] * padding_size)
    return _bytes[:-padding_size]

''' Returns AES-CBC encrypted ciphertext without IV '''
def aes_cbc_encrypt(aes, iv, bytes):
    assert len(iv) == aes.block_size and len(bytes) % aes.block_size == 0
    blks = [iv]
    for blk in chop(bytes, aes.block_size):
        blks.append(aes.encrypt(xor_bytes(blk, blks[-1])))
    return b''.join(blks[1:])

''' Takes as input ciphertext bytes separate from the IV '''
def aes_cbc_decrypt(aes, iv, bytes):
    assert len(iv) == aes.block_size and len(bytes) % aes.block_size == 0
    blks = [iv] + chop(bytes, aes.block_size)
    return b''.join([xor_bytes(aes.decrypt(blks[i]), blks[i-1]) for i in range(1, len(blks))])

def aes_ecb_encrypt(aes, pt):
    assert len(pt) % aes.block_size == 0
    return b''.join([aes.encrypt(blk) for blk in chop(pt, aes.block_size)])

def aes_ecb_decrypt(aes, ct):
    assert len(ct) % aes.block_size == 0
    return b''.join([aes.decrypt(blk) for blk in chop(ct, aes.block_size)])

def detect_blk_enc_mode(encryption_oracle, blk_size):
    return 'ECB' if has_repeated_blocks(encryption_oracle(b'A'*blk_size*3), blk_size) else 'CBC'

def detect_blk_size(encryption_oracle):
    orig_ct_len, test = len(encryption_oracle(b'')), b'A'
    while len(encryption_oracle(test)) == orig_ct_len:
        test += b'A'
    return len(encryption_oracle(test)) - orig_ct_len

def ecb_decrypt_appended_bytes(ecb_encryption_oracle):
    blk_size = detect_blk_size(ecb_encryption_oracle)
    assert detect_blk_enc_mode(ecb_encryption_oracle, blk_size) == 'ECB'

    ''' Find the insertion point of our input '''
    bef, aft = chop(ecb_encryption_oracle(b''), blk_size), chop(ecb_encryption_oracle(b'A'), blk_size)
    start_blk = None
    for i in range(len(bef)):
        if bef[i] == aft[i]: continue
        else:
            start_blk = i
            break

    ''' If start_blk is None -> b'A' is appended to plaintext -> nothing is appended '''
    if start_blk is None:
        return b''

    ''' We need to know how much to pad to control the block after start_blk '''
    test = b'A' * 2 * blk_size
    while not has_repeated_blocks(ecb_encryption_oracle(test), blk_size):
        test += b'A'
    left_padding = b'A' * (len(test) - 2 * blk_size)
    if left_padding == b'':
        start_blk -= 1

    ''' Discover the length of the appended secret '''
    test, orig_ct = left_padding, ecb_encryption_oracle(left_padding)
    while len(ecb_encryption_oracle(test)) == len(orig_ct):
        test += b'A'
    secret_len = (len(orig_ct)//blk_size - (start_blk + 1)) * blk_size - (len(test) - len(left_padding))

    ''' Bruteforce the secret, byte by byte '''
    secret_blocks = -(-secret_len // blk_size)
    test = left_padding + b'A' * secret_blocks * blk_size
    ctrl_blk = start_blk + secret_blocks
    secret = b''
    for _ in range(secret_len):
        test = test[:-1]
        needle = chop(ecb_encryption_oracle(test), blk_size)[ctrl_blk]
        for b in range(256):
            test_in = test + secret + bytes([b])
            if chop(ecb_encryption_oracle(test_in), blk_size)[ctrl_blk] == needle:
                secret += bytes([b])
                break
    return secret

def cbc_padding_oracle_attack(oracle, iv, ct, blk_size):
    blocks = [iv] + chop(ct, blk_size)
    num_blocks = len(blocks)
    decrypted_blks = [None for _ in range(num_blocks - 1)]
    for i in range(num_blocks - 2, -1, -1):
        decrypted_blk = [b'\x00' for _ in range(blk_size)]
        for j in range(blk_size - 1, -1, -1):
            xs = []
            should_mutate_second_byte = False
            while len(xs) != 1:
                xs.clear()
                pad_len = blk_size - j
                desired_padding = pkcs7_pad(b'\x00' * (blk_size - pad_len), blk_size)
                decrypted_blk_bytes = b''.join(decrypted_blk)
                for b in range(256):
                    test_blk = b'\x00' * j + bytes([b]) + b'\x00' * (blk_size - j - 1)
                    if should_mutate_second_byte:
                        test_blk = xor_bytes(test_blk, b'\x00' * (blk_size - 2) + b'\xFF\x00')
                    test_blks = blocks[::]
                    test_blks[i] = xor_bytes(test_blk, xor_bytes(desired_padding, xor_bytes(decrypted_blk_bytes, blocks[i])))
                    if oracle(test_blks[0], b''.join(test_blks[1:])):
                        xs.append(bytes([b]))

                '''
                The first byte is a bit trickier, since we can have 
                xx ... xx 01, xx ... 02 02 (if second byte is 02), etc.
                Hence, we mutate the second last byte to break the chain.
                E.g. xx ... 02 yy -> xx ... FD yy so that only xx ... FD 01 would be
                a valid padding
                '''
                if j == blk_size - 1 and len(xs) > 1 and not should_mutate_second_byte:
                    should_mutate_second_byte = True

            decrypted_blk[j] = xs[0]
        decrypted_blks[i] = b''.join(decrypted_blk)
        blocks = blocks[:-1]
    return b''.join(decrypted_blks)
        