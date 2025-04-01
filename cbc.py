import random
import string
from utils import XOR
from AES_128 import encode_aes_128, decode_aes_128


def pad(data:bytes)->bytes:
    pad_size = 16 - len(data)%16
    padding = bytes([pad_size]*pad_size)
    return data + padding

def unpad(data:bytes)->bytes:
    pad_size = data[-1] 
    return data[:-pad_size]

def to_blocks(data: bytes, block_size: int):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def AES_CBC_encrypt(plain_text: bytes, key:bytes, start_iv: bytes)->bytes:
    iv = start_iv
    pad_plain_text = pad(plain_text)
    blocks = to_blocks(pad_plain_text, 16)
    cipher_text = b''
    for block in blocks:
        cipher_block = encode_aes_128(XOR(iv, block), key)
        cipher_text += cipher_block
        iv = cipher_block
    return cipher_text

def AES_CBC_decrypt(cipher: bytes, key:bytes, start_iv: bytes)->bytes:
    lst_cipher_block = to_blocks(cipher, 16)
    iv = start_iv
    plain_text = b''
    for block in lst_cipher_block:
        plain_block = decode_aes_128(block, key)
        plain_block = XOR(plain_block, iv)
        iv = block
        plain_text += plain_block

    return unpad(plain_text)
        
   
