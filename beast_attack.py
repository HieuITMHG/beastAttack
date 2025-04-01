import random
import string
from cbc import AES_CBC_encrypt
from utils import XOR
from AES_128 import encode_aes_128

BLOCK_SIZE = 16
SESSION_KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=BLOCK_SIZE)).encode('utf-8')
request = b"""GET /dashboard HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9\nCookie: SESSIONID=SECRET1234\nConnection: close\n"""
start_iv = ''.join(random.choices(string.ascii_letters + string.digits, k=BLOCK_SIZE)).encode('utf-8')

class Brower:
    def __init__(self, data:bytes, key:bytes|None = None, iv:bytes|None=None):
        if key is None:
            key = bytes([random.randint(0, 255) for _ in range(16)])
            
        if iv is None:
            iv =  key = bytes([random.randint(0, 255) for _ in range(16)])

        self.key = key
        self.iv = iv
        self.data = data
    
    def send_data_to_server(self, data:bytes):
        ciphers = AES_CBC_encrypt(data, self.key, self.iv)
        iv = ciphers[-BLOCK_SIZE]
        return ciphers

def attack(victim:Brower)->bytes:
    pass

if __name__ == "__main__":
    victim = Brower(b"this data is secret")
    result = attack(victim)
    print("Attack result: {}".format(result))