from gmssl import sm4, sm2, sm3, func
import os
import sys

def generate_random_data(size):
    return os.urandom(size)

def sm4_encrypt(key, data):
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    return cipher.crypt_cbc(b'\0' * 16, data)

def sm4_decrypt(key, data):
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_DECRYPT)
    return cipher.crypt_cbc(b'\0' * 16, data)

def sm2_sign(private_key, data):
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key='')
    hash_data = sm3.sm3_hash(func.bytes_to_list(data))
    k = func.random_hex(64)  # 256-bit random hex for K
    signature = sm2_crypt.sign(bytes.fromhex(hash_data), k)
    return signature.encode('utf-8')

def sm2_verify(public_key, data, signature):
    sm2_crypt = sm2.CryptSM2(private_key='', public_key=public_key)
    hash_data = sm3.sm3_hash(func.bytes_to_list(data))
    return sm2_crypt.verify(signature.decode('utf-8'), bytes.fromhex(hash_data))

def sm2_encrypt(public_key, data):
    sm2_crypt = sm2.CryptSM2(private_key='', public_key=public_key)
    return sm2_crypt.encrypt(data)

def sm2_decrypt(private_key, data):
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key='')
    return sm2_crypt.decrypt(data)

def generate_sm2_key_pair():
    private_key = func.random_hex(64)  # 256-bit private key
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key='')
    public_key = sm2_crypt._kg(int(private_key, 16), sm2.default_ecc_table['g'])
    return private_key, public_key

def save_key_to_file(filename, key):
    with open(filename, 'w') as f:
        f.write(key)

def load_key_from_file(filename):
    with open(filename, 'r') as f:
        return f.read().strip()

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py [mode] [arguments]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'generate_keys':
        private_key, public_key = generate_sm2_key_pair()
        save_key_to_file('private_key.pem', private_key)
        save_key_to_file('public_key.pem', public_key)
        print("Generated and saved SM2 keys.")

    elif mode == 'encrypt':
        private_key = load_key_from_file('private_key.pem')
        public_key = load_key_from_file('public_key.pem')

        # 生成随机数据
        data = generate_random_data(5 * 1024 * 1024)
        with open('plaintext_file', 'wb') as f:
            f.write(data)

        # 生成对称密钥
        sym_key = generate_random_data(16)
        with open('symmetric_key', 'wb') as f:
            f.write(sym_key)

        # 加密数据
        encrypted_data = sm4_encrypt(sym_key, data)
        with open('encrypted_file', 'wb') as f:
            f.write(encrypted_data)

        # 生成数字签名
        signature = sm2_sign(private_key, data)
        with open('signature', 'wb') as f:
            f.write(signature)

        # 用乙方的公钥加密对称密钥
        encrypted_key = sm2_encrypt(public_key, sym_key)
        with open('encrypted_key', 'wb') as f:
            f.write(encrypted_key)

    elif mode == 'decrypt_key':
        encrypted_key_file = sys.argv[2]
        private_key = load_key_from_file('private_key.pem')
        with open(encrypted_key_file, 'rb') as f:
            encrypted_key = f.read()
        decrypted_key = sm2_decrypt(private_key, encrypted_key)
        with open('recovered_key', 'wb') as f:
            f.write(decrypted_key)

    elif mode == 'decrypt_file':
        encrypted_file = sys.argv[2]
        recovered_key_file = sys.argv[3]
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        with open(recovered_key_file, 'rb') as f:
            recovered_key = f.read()
        decrypted_data = sm4_decrypt(recovered_key, encrypted_data)
        with open('recovered_plaintext_file', 'wb') as f:
            f.write(decrypted_data)

    elif mode == 'verify_signature':
        signature_file = sys.argv[2]
        recovered_plaintext_file = sys.argv[3]
        with open(signature_file, 'rb') as f:
            signature = f.read()
        with open(recovered_plaintext_file, 'rb') as f:
            recovered_data = f.read()
        public_key = load_key_from_file('public_key.pem')
        is_valid = sm2_verify(public_key, recovered_data, signature)
        print('Signature valid:', is_valid)

    elif mode == 'check_consistency':
        plaintext_file = sys.argv[2]
        recovered_plaintext_file = sys.argv[3]
        with open(plaintext_file, 'rb') as f:
            plaintext_data = f.read()
        with open(recovered_plaintext_file, 'rb') as f:
            recovered_data = f.read()
        if plaintext_data == recovered_data:
            print('success')
        else:
            print('failure')

if __name__ == '__main__':
    main()
