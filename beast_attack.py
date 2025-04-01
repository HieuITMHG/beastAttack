import random
import string
from cbc import AES_CBC_encrypt, AES_CBC_decrypt
from utils import XOR
from AES_128 import encode_aes_128, decode_aes_128

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
        self.iv = ciphers[-BLOCK_SIZE:]
        return ciphers

def find_data_len(victim:Brower):
    '''
    l : kich thuoc cipher ung voi data
    l = len(data) + padding

    chen du lieu vao cho den khi kich thuoc cipher doi
    khi do, tuc la padding = 0
    l = len(data) + n
    len(data) = l - n
    '''
    r1 = victim.send_data_to_server(victim.data)
    l = len(r1)
    
    n = 0
    while(True):
        n += 1
        r2 = victim.send_data_to_server(b'X'*n + victim.data)
        if(len(r2) != l):
            break
    return (l)-n
            

def attack(victim:Brower)->bytes:

    data_len = 0
    known_data = b""

    # Xac dinh kich thuoc du lieu
    data_len = find_data_len(victim)
    print("Data len = ", data_len)
    # tao 1 request de lay iv
    r = victim.send_data_to_server(b"kjsfhjshfshkdf")
    iv = r[-16:]


    while(len(known_data) != data_len):
        # 
        index = len(known_data) # byte can tim tiep theo
        block_id = index//16 #byte can tim o block thu may (tinh tu 0)
        
        inject_size = 15 - (index%16)
        inject = inject_size * b'X'

        # tao request de lay cipher mau(cua data dung)
        r1 = victim.send_data_to_server(inject + victim.data)

        # lay cipher mau (ti nua so sanh)
        # cipher cua block_id
        sample_cipher = r1[16*block_id: 16*block_id+16]

        # prev_cipher la cipher xor voi plaintext block_id

        prev_cipher = None
        if block_id == 0:
            prev_cipher = iv
        else:
            # cipher text block_id -1
            start = (block_id -1)*16
            end = start + 16
            print("prev cipher", start, end)
            prev_cipher = r1[start:end]

        # update iv
        iv = r1[-16:]
        # print(iv)
        # print(type(iv))
        # debug
        print('------------------------------------------')
        print ("know: ", known_data)
        print("index:", index)
        print("block id:", block_id)
        print("inject size: ", inject_size)
        print("inject value: ", inject)
        print('------------------------------------------')
        for guess in [int.to_bytes(x) for x in range(256)]:
            p = None
            if(len(known_data) >= 15):
                p = known_data[-15:] + guess
            else:
                p = b'X'*(15 - len(known_data))  + known_data + guess
            
            p = XOR(p, iv)
            p = XOR(p, prev_cipher)

            # tao request de so sanh
            r2 = victim.send_data_to_server(p + victim.data)
            iv = r2[-16:]

            # so sanh
            if r2[0:16] == sample_cipher:
                print("Tim duoc byte thu", len(known_data),":", guess)
                
                known_data += guess
                print("Biet duoc:", known_data)
                break # dung vong
            if(guess == int.to_bytes(255)):
                raise RuntimeError(":)))")
    return known_data

if __name__ == "__main__":
    victim = Brower(b"this data is secret hacker can not see(~ maybe not)123409876gf")
    # victim = Brower(request)
    result = attack(victim)
    print("Attack result: {}".format(result))

