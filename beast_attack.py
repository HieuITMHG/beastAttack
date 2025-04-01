import random
import string
from utils import XOR
from AES_128 import encode_aes_128

BLOCK_SIZE = 16
SESSION_KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=BLOCK_SIZE)).encode('utf-8')
request = b"""GET /dashboard HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9\nCookie: SESSIONID=SECRET1234\nConnection: close\n"""
start_iv = ''.join(random.choices(string.ascii_letters + string.digits, k=BLOCK_SIZE)).encode('utf-8')

def pad(data:bytes, block_size)->bytes:
        pad_size = block_size - len(data)%block_size
        padding = bytes([pad_size]*pad_size)
        return data + padding

def to_blocks(data: bytes, block_size: int):
    data = pad(data, BLOCK_SIZE)
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def AES_CBC_encrypt(plain_text: bytes, start_iv: bytes):
    iv = start_iv
    blocks = to_blocks(plain_text, BLOCK_SIZE)
    cipher_text = []
    for block in blocks:
        cipher_block = encode_aes_128(XOR(iv, block), SESSION_KEY)
        cipher_text.append(cipher_block)
        iv = cipher_block
    return cipher_text

def get_injected_block(guess_block: bytes, current_iv: bytes, previous_iv: bytes):
    return XOR(XOR(guess_block, current_iv), previous_iv)

def beast_attack():
   

if __name__ == "__main__":
    print(AES_CBC_encrypt(plain_text=request, start_iv=start_iv))