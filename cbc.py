import random
import string
from utils import XOR
from AES_128 import encode_aes_128


def pad(data:bytes)->bytes:
    pad_size = 16 - len(data)%16
    padding = bytes([pad_size]*pad_size)
    return data + padding

def to_blocks(data: bytes, block_size: int):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def AES_CBC_encrypt(plain_text: bytes, key:bytes, start_iv: bytes):
    iv = start_iv
    pad_plain_text = pad(plain_text)
    blocks = to_blocks(pad_plain_text, 16)
    cipher_text = []
    for block in blocks:
        cipher_block = encode_aes_128(XOR(iv, block), key)
        cipher_text.append(cipher_block)
        iv = cipher_block
    return cipher_text
   
