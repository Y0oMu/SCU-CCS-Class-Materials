# 数据传输安全实验

本项目实现了使用SM4、SM2和SM3算法对数据进行加密、签名和验证，以确保数据传输的机密性、完整性和认证性。

## 环境配置

首先，确保你已经安装了Python和`gmssl`库。

```bash
pip install gmssl
```

## 文件说明

- `script.py`: 主程序文件，包含加密、解密、签名和验证的实现。
- `private_key.pem`: 生成的SM2私钥文件。
- `public_key.pem`: 生成的SM2公钥文件。
- `plaintext_file`: 生成的随机数据文件。
- `symmetric_key`: 生成的对称密钥文件。
- `encrypted_file`: 加密后的数据文件。
- `signature`: 生成的数字签名文件。
- `encrypted_key`: 加密后的对称密钥文件。
- `recovered_key`: 解密后的对称密钥文件。
- `recovered_plaintext_file`: 解密后的数据文件。

## 使用说明

### 1. 生成SM2密钥对

运行以下命令生成SM2密钥对，并将密钥保存到文件：

```bash
python script.py generate_keys
```

### 2. 加密数据和生成签名

运行以下命令生成随机数据，对数据进行SM4加密，并生成SM2签名和加密后的对称密钥：

```bash
python script.py encrypt
```

### 3. 解密对称密钥

运行以下命令使用私钥解密对称密钥：

```bash
python script.py decrypt_key encrypted_key
```

### 4. 解密数据

运行以下命令使用解密后的对称密钥解密数据文件：

```bash
python script.py decrypt_file encrypted_file recovered_key
```

### 5. 验证签名

运行以下命令验证解密后的数据签名是否正确：

```bash
python script.py verify_signature signature recovered_plaintext_file
```

### 6. 数据一致性检查

运行以下命令检查原始数据和解密后的数据是否一致：

```bash
python script.py check_consistency plaintext_file recovered_plaintext_file
```

## 实验结果

通过上述步骤，可以验证数据的加密、签名和解密过程，确保数据的机密性、完整性和认证性。

## 注意事项

- 请确保使用的Python版本和`gmssl`库版本兼容。
- 请根据实际情况调整文件路径和文件名。
