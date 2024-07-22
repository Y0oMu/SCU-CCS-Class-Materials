import argparse
import time
from Crypto.Cipher import DES
from binascii import hexlify, unhexlify

def des_encrypt(plain_text, key, iv, mode):
    cipher = None
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=8)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv)
    else:
        raise ValueError("Unsupported mode")

    encrypted_text = cipher.encrypt(plain_text)
    return hexlify(encrypted_text).decode()

def des_decrypt(cipher_text, key, iv, mode):
    cipher = None
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=8)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv)
    else:
        raise ValueError("Unsupported mode")

    encrypted_text = unhexlify(cipher_text)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text

def load_file(file_path, hex_format=True):
    with open(file_path, 'rb') as file:
        content = file.read().strip()
        if hex_format:
            content = unhexlify(content)
        return content

def save_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

def generate_random_data(size):
    return bytes([i % 256 for i in range(size)])

def benchmark_mode(mode, key, iv, test_data):
    start_time = time.time()
    for _ in range(20):
        encrypted_data = des_encrypt(test_data, key, iv, mode)
    encryption_time = (time.time() - start_time) * 1000  # milliseconds

    start_time = time.time()
    for _ in range(20):
        decrypted_data = des_decrypt(encrypted_data, key, iv, mode)
    decryption_time = (time.time() - start_time) * 1000  # milliseconds

    data_size_mb = len(test_data) * 20 / (1024 * 1024)
    encryption_speed = data_size_mb / (encryption_time / 1000)
    decryption_speed = data_size_mb / (decryption_time / 1000)

    return encryption_time, decryption_time, encryption_speed, decryption_speed

def main():
    parser = argparse.ArgumentParser(description='DES Encryption/Decryption')
    parser.add_argument('-p', '--plainfile', required=True, help='Path to plaintext file')
    parser.add_argument('-k', '--keyfile', required=True, help='Path to key file')
    parser.add_argument('-v', '--vifile', help='Path to IV file')
    parser.add_argument('-m', '--mode', required=True, choices=['ECB', 'CBC', 'CFB', 'OFB'], help='Encryption mode')
    parser.add_argument('-c', '--cipherfile', required=True, help='Path to output cipher file')

    args = parser.parse_args()

    plain_text = load_file(args.plainfile)
    key = load_file(args.keyfile)
    iv = load_file(args.vifile) if args.vifile else None

    cipher_text = des_encrypt(plain_text, key, iv, args.mode)
    save_file(args.cipherfile, cipher_text.encode().upper())
    print(cipher_text.encode().upper())
    # Benchmarking
    test_data = generate_random_data(5 * 1024 * 1024)  # 5 MB test data
    encryption_time, decryption_time, encryption_speed, decryption_speed = benchmark_mode(args.mode, key, iv, test_data)

    print(f"Encryption time: {encryption_time:.2f} ms")
    print(f"Decryption time: {decryption_time:.2f} ms")
    print(f"Encryption speed: {encryption_speed:.2f} MB/s")
    print(f"Decryption speed: {decryption_speed:.2f} MB/s")

if __name__ == '__main__':
    main()
