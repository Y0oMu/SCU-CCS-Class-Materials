import os
import time
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().strip()

def write_file(file_path, data):
    with open(file_path, 'w') as file:
        file.write(data)

def aes_encrypt_decrypt(mode, data, key, iv=None, operation='encrypt'):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=8)
    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv)
    else:
        raise ValueError("Invalid mode")

    if operation == 'encrypt':
        if mode == 'ECB' or mode == 'CBC':
            if len(data) % AES.block_size != 0:
                data = pad(data, AES.block_size)
            ciphertext = cipher.encrypt(data)
        else:
            ciphertext = cipher.encrypt(data)
        return hexlify(ciphertext).decode('utf-8') if isinstance(data, bytes) else ciphertext
    elif operation == 'decrypt':
        ciphertext = unhexlify(data) if isinstance(data, str) else data
        decrypted = cipher.decrypt(ciphertext)
        if mode == 'ECB' or mode == 'CBC':
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError:
                pass  # Ignore padding errors for performance test
        return decrypted
    else:
        raise ValueError("Invalid operation")

def generate_random_data(size):
    return os.urandom(size)

def performance_test(mode, key, iv=None):
    data = generate_random_data(5 * 1024 * 1024)  # 5MB random data
    start_encrypt_time = time.time()
    for _ in range(20):
        encrypted_data = aes_encrypt_decrypt(mode, data, key, iv, operation='encrypt')
    end_encrypt_time = time.time()

    start_decrypt_time = time.time()
    for _ in range(20):
        aes_encrypt_decrypt(mode, encrypted_data, key, iv, operation='decrypt')
    end_decrypt_time = time.time()

    encrypt_time = (end_encrypt_time - start_encrypt_time) * 1000  # ms
    decrypt_time = (end_decrypt_time - start_decrypt_time) * 1000  # ms

    print(f"{mode} Encrypt Time: {encrypt_time} ms, Speed: {100 / (encrypt_time / 1000)} MB/s")
    print(f"{mode} Decrypt Time: {decrypt_time} ms, Speed: {100 / (decrypt_time / 1000)} MB/s")

def main():
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption')
    parser.add_argument('-p', '--plainfile', required=True, help='Path to the plaintext file')
    parser.add_argument('-k', '--keyfile', required=True, help='Path to the key file')
    parser.add_argument('-v', '--vifile', help='Path to the initialization vector file')
    parser.add_argument('-m', '--mode', required=True, choices=['ECB', 'CBC', 'CFB', 'OFB'], help='Encryption mode')
    parser.add_argument('-c', '--cipherfile', required=True, help='Path to the ciphertext file')
    args = parser.parse_args()

    plaintext = unhexlify(read_file(args.plainfile))
    key = unhexlify(read_file(args.keyfile))
    iv = unhexlify(read_file(args.vifile)) if args.vifile else None

    ciphertext = aes_encrypt_decrypt(args.mode, plaintext, key, iv, operation='encrypt')
    write_file(args.cipherfile, ciphertext)
    print(ciphertext)
    decrypted_text = aes_encrypt_decrypt(args.mode, ciphertext, key, iv, operation='decrypt')
    print("Decryption successful:", decrypted_text == plaintext)

    # Performance test
    performance_test(args.mode, key, iv)

if __name__ == "__main__":
    main()
