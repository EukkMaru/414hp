import _utils.math_utils as math
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json
from functools import reduce
import argparse

def command_line_args():
    parser = argparse.ArgumentParser(description="Client for the Secure Messaging System")
    parser.add_argument("-t", "--task", metavar="<task number>", help="task number", type=int, required=True)
    parser.add_argument("-p", "--path", metavar="<path to file>", help="path to log file", type=str, required=True)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    task = args.task
    path = args.path

    with open(path, 'r') as file:
        logs = file.readlines()
    data = [json.loads(line) for line in logs]
    
    if task == 1:
        e = data[1]["public"]  
        n = data[1]["parameter"]["n"]  
        encrypted_key = data[2]["encrypted_key"]  
        encrypted_message_b64 = data[3]["encryption"]  

        print(f"e: {e}, n: {n}, encrypted_key: {encrypted_key}, encrypted_message_b64: {encrypted_message_b64}")
        
        p, q = None, None

        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                p, q = i, n // i
                
                if math.is_prime(p) and math.is_prime(q):
                    break

        print(f"p = {p}, q = {q}")
        
        phi = (p - 1) * (q - 1)

        m0, x0, x1 = phi, 0, 1
        a = e
        while a > 1:
            q = a // m0
            m0, a = a % m0, m0
            x0, x1 = x1 - q * x0, x0

        d = x1 + phi if x1 < 0 else x1

        print(f"d = {d}")
        
        aes_key_bytes = b''.join(bytes([pow(byte, d, n)]) for byte in encrypted_key)

        print(f"AES Key: {aes_key_bytes.hex()}")
        
        ciphertext = base64.b64decode(encrypted_message_b64)
        cipher = AES.new(aes_key_bytes, AES.MODE_ECB)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        print("\nDecrypted Message:", decrypted_message.decode('ascii'))
    elif task == 2:
        p = data[1]['parameter']['p']
        g = data[1]['parameter']['g']
        g_a_modp = data[1]['public']
        g_b_modp = data[2]['public']
        encrypted_message_1 = data[3]['encryption']
        encrypted_message_2 = data[4]['encryption']

        print(f"p: {p}, g: {g}, g_a_modp: {g_a_modp}, g_b_modp: {g_b_modp}")
        
        a, b = None, None

        for x in range(1, p):
            if pow(g, x, p) == g_a_modp:
                a = x
                break
            
        for y in range(1, p):
            if pow(g, y, p) == g_b_modp:
                b = y
                break

        print(f"a = {a}, b = {b}")
        
        key = pow(g, a*b, p)

        bytekey = int.to_bytes(key, 2, 'big')

        aes_key = reduce(lambda x, y: x + y, [bytekey] * 16)
        
        print(f"AES Key: {aes_key.hex()}")
        
        ciphertext1 = base64.b64decode(encrypted_message_1)
        ciphertext2 = base64.b64decode(encrypted_message_2)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_message_1 = unpad(cipher.decrypt(ciphertext1), AES.block_size)
        decrypted_message_2 = unpad(cipher.decrypt(ciphertext2), AES.block_size)
        print("\nMessage 1:", decrypted_message_2.decode('ascii'), "\nMessage 2:", decrypted_message_1.decode('ascii'))
    else:
        print("Invalid task number")
        
if __name__ == "__main__":
    main()