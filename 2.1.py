import os
import random
import string
import hashlib
import base64
import zlib
import json
import tempfile
from datetime import datetime
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, PKCS1_OAEP
from Crypto.Cipher import ARC4 as RC4, Salsa20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Signature import pkcs1_15
import argon2.low_level
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar


class TraditionalEncryptor:
    def __init__(self):
        self.supported_algorithms = {
            '1': 'AES-256-CBC',
            '2': 'RSA-4096',
            '3': 'Blowfish',
            '4': 'ChaCha20',
            '5': 'DES',
            '6': '3DES',
            '7': 'RC4',
            '8': 'Salsa20',
            '9': 'MFDG-Hybrid'
        }
        self.compression_level = 6
        self.key_storage_path = "encryption_keys"
        self._setup_key_storage()

    def _setup_key_storage(self):
        """创建密钥存储目录"""
        if not os.path.exists(self.key_storage_path):
            os.makedirs(self.key_storage_path, mode=0o700)
            with open(os.path.join(self.key_storage_path, '.gitignore'), 'w') as f:
                f.write("*\n!.gitignore")

    def generate_random_suffix(self):
        """生成2~12位的随机字母和数字（包含至少2个数字）"""
        length = random.randint(2, 12)
        digits = random.choices(string.digits, k=2)
        chars = random.choices(string.ascii_letters + string.digits, k=length - 2)
        result = digits + chars
        random.shuffle(result)
        return ''.join(result)

    def caesar_cipher(self, text, shift):
        """凯撒密码加密/解密"""
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) + shift - 65) % 26 + 65))
            elif char.islower():
                result.append(chr((ord(char) + shift - 97) % 26 + 97))
            else:
                result.append(char)
        return ''.join(result)

    def get_shift_from_filename(self, filename):
        """从文件名中获取第一个数字作为凯撒位移"""
        for char in filename:
            if char.isdigit():
                return int(char)
        return 0

    def _generate_mfdg_key(self, base_key=None, salt=None, factors=None):
        """生成MFDG-Hybrid密钥材料"""
        if base_key is None:
            base_key = base64.b64encode(get_random_bytes(32)).decode('utf-8')

        if salt is None:
            salt = get_random_bytes(32)
        if factors is None:
            hardware_fingerprint = hashlib.sha256(b'simulated_hardware_id').digest()
            time_factor = datetime.now().strftime("%Y%m%d%H%M%S").encode()
            random_challenge = get_random_bytes(16)
            factors = hardware_fingerprint + time_factor + random_challenge

        raw_hash = argon2.low_level.hash_secret_raw(
            secret=base_key.encode() + salt + factors,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=argon2.low_level.Type.ID
        )
        return {
            'enc_key': raw_hash[:32],
            'hmac_key': raw_hash[32:],
            'salt': salt,
            'factors': factors,
            'base_key': base_key
        }

    def _save_decryption_key(self, filename, key_data):
        """安全保存解密密钥"""
        key_file = os.path.join(self.key_storage_path, f"{filename}.key")
        with open(key_file, 'w') as f:
            json.dump({
                'version': 'MFDG-Key-v1',
                'created': datetime.now().isoformat(),
                'base_key': key_data['base_key'],
                'file_association': filename
            }, f)
        os.chmod(key_file, 0o600)

    def _load_decryption_key(self, filename):
        """加载解密密钥"""
        key_file = os.path.join(self.key_storage_path, f"{filename}.key")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"未找到密钥文件: {key_file}")

        with open(key_file, 'r') as f:
            key_data = json.load(f)

        if key_data.get('version') != 'MFDG-Key-v1':
            raise ValueError("密钥文件版本不兼容")

        return key_data['base_key']

    def _add_content_hash(self, content):
        """为内容添加哈希验证"""
        return f"{content}:{hashlib.sha3_256(content.encode()).hexdigest()}"

    def _verify_content_hash(self, decrypted_content):
        """验证内容哈希"""
        content, content_hash = decrypted_content.rsplit(':', 1)
        calculated_hash = hashlib.sha3_256(content.encode()).hexdigest()
        if not self._constant_time_compare(calculated_hash.encode(), content_hash.encode()):
            raise ValueError("内容哈希验证失败")
        return content

    def encrypt_aes(self, content, key):
        """AES加密 (CBC模式)"""
        content_with_hash = self._add_content_hash(content)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content_with_hash.encode(), AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_aes(self, encrypted_data, key):
        """AES解密"""
        iv = encrypted_data[:AES.block_size]
        ct = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_content = unpad(cipher.decrypt(ct), AES.block_size).decode()
        return self._verify_content_hash(decrypted_content)

    def generate_rsa_keypair(self, key_size=4096):
        """生成RSA密钥对"""
        key = RSA.generate(key_size)
        return key.publickey().export_key(), key.export_key()

    def encrypt_rsa(self, content, public_key):
        """RSA加密"""
        content_with_hash = self._add_content_hash(content)
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        return cipher.encrypt(content_with_hash.encode())

    def decrypt_rsa(self, encrypted_data, private_key):
        """RSA解密"""
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        decrypted_content = cipher.decrypt(encrypted_data).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_blowfish(self, content, key):
        """Blowfish加密"""
        content_with_hash = self._add_content_hash(content)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content_with_hash.encode(), Blowfish.block_size))
        return cipher.iv + ct_bytes

    def decrypt_blowfish(self, encrypted_data, key):
        """Blowfish解密"""
        iv = encrypted_data[:Blowfish.block_size]
        ct = encrypted_data[Blowfish.block_size:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        decrypted_content = unpad(cipher.decrypt(ct), Blowfish.block_size).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_chacha20(self, content, key):
        """ChaCha20加密"""
        content_with_hash = self._add_content_hash(content)
        cipher = ChaCha20.new(key=key)
        ct_bytes = cipher.encrypt(content_with_hash.encode())
        return cipher.nonce + ct_bytes

    def decrypt_chacha20(self, encrypted_data, key):
        """ChaCha20解密"""
        nonce = encrypted_data[:8]
        ct = encrypted_data[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_content = cipher.decrypt(ct).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_des(self, content, key):
        """DES加密"""
        content_with_hash = self._add_content_hash(content)
        cipher = DES.new(key, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content_with_hash.encode(), DES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_des(self, encrypted_data, key):
        """DES解密"""
        iv = encrypted_data[:DES.block_size]
        ct = encrypted_data[DES.block_size:]
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        decrypted_content = unpad(cipher.decrypt(ct), DES.block_size).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_3des(self, content, key):
        """3DES加密"""
        content_with_hash = self._add_content_hash(content)
        cipher = DES3.new(key, DES3.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content_with_hash.encode(), DES3.block_size))
        return cipher.iv + ct_bytes

    def decrypt_3des(self, encrypted_data, key):
        """3DES解密"""
        iv = encrypted_data[:DES3.block_size]
        ct = encrypted_data[DES3.block_size:]
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        decrypted_content = unpad(cipher.decrypt(ct), DES3.block_size).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_rc4(self, content, key):
        """RC4加密"""
        content_with_hash = self._add_content_hash(content)
        cipher = RC4.new(key)
        return cipher.encrypt(content_with_hash.encode())

    def decrypt_rc4(self, encrypted_data, key):
        """RC4解密"""
        cipher = RC4.new(key)
        decrypted_content = cipher.decrypt(encrypted_data).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_salsa20(self, content, key):
        """Salsa20加密"""
        content_with_hash = self._add_content_hash(content)
        nonce = get_random_bytes(8)
        cipher = Salsa20.new(key=key, nonce=nonce)
        ct_bytes = cipher.encrypt(content_with_hash.encode())
        return nonce + ct_bytes

    def decrypt_salsa20(self, encrypted_data, key):
        """Salsa20解密"""
        nonce = encrypted_data[:8]
        ct = encrypted_data[8:]
        cipher = Salsa20.new(key=key, nonce=nonce)
        decrypted_content = cipher.decrypt(ct).decode()
        return self._verify_content_hash(decrypted_content)

    def encrypt_mfdg_hybrid(self, content, base_key=None):
        """MFDG-Hybrid加密"""
        key_material = self._generate_mfdg_key(base_key)

        # 计算内容哈希
        content_with_hash = self._add_content_hash(content)

        # 第一层：AES加密
        aes_encrypted = self.encrypt_aes(content_with_hash, key_material['enc_key'])

        # 第二层：ChaCha20加密
        chacha_key = hashlib.sha256(key_material['enc_key'] + key_material['factors'][:16]).digest()
        chacha_encrypted = self.encrypt_chacha20(aes_encrypted.hex(), chacha_key)

        # 第三层：压缩
        compressed = zlib.compress(chacha_encrypted, level=self.compression_level)

        # HMAC验证
        hmac = hashlib.sha3_256(key_material['hmac_key'] + compressed).digest()

        return {
            'version': 'MFDG-Hybrid-v2',
            'salt': key_material['salt'].hex(),
            'dynamic_factors': key_material['factors'].hex(),
            'hmac': hmac.hex(),
            'encrypted_data': compressed.hex()
        }, key_material['base_key']

    def decrypt_mfdg_hybrid(self, encrypted_data, base_key):
        """MFDG-Hybrid解密"""
        # 提取组件
        salt = bytes.fromhex(encrypted_data['salt'])
        factors = bytes.fromhex(encrypted_data['dynamic_factors'])
        hmac = bytes.fromhex(encrypted_data['hmac'])
        compressed = bytes.fromhex(encrypted_data['encrypted_data'])

        # 重新生成密钥
        key_material = self._generate_mfdg_key(
            base_key=base_key,
            salt=salt,
            factors=factors
        )

        # 验证HMAC
        expected_hmac = hashlib.sha3_256(key_material['hmac_key'] + compressed).digest()
        if not self._constant_time_compare(hmac, expected_hmac):
            raise ValueError("HMAC验证失败 - 数据可能被篡改")

        # 解压缩
        decompressed = zlib.decompress(compressed)

        # 第二层：ChaCha20解密
        chacha_key = hashlib.sha256(key_material['enc_key'] + factors[:16]).digest()
        chacha_decrypted = self.decrypt_chacha20(decompressed, chacha_key)

        # 第一层：AES解密
        aes_encrypted = bytes.fromhex(chacha_decrypted)
        decrypted_content = self.decrypt_aes(aes_encrypted, key_material['enc_key'])

        # 验证内容哈希
        return self._verify_content_hash(decrypted_content)

    def _constant_time_compare(self, a, b):
        """恒定时间比较"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def encrypt_file_gui(self, filename, content, algorithm_num):
        """为GUI优化的加密方法"""
        # 生成随机后缀
        suffix = self.generate_random_suffix()

        full_filename = f"{filename}_{suffix}"
        encrypted_data = None
        key_info = {}

        # 使用文件名作为基础密钥
        base_key = filename.encode()
        key = hashlib.sha512(base_key).digest()

        if algorithm_num == '1':  # AES
            encrypted_data = self.encrypt_aes(content, key[:32])
            full_filename += ".aes"

        elif algorithm_num == '2':  # RSA
            public_key, private_key = self.generate_rsa_keypair()
            encrypted_data = self.encrypt_rsa(content, public_key)
            with open(f"{full_filename}.priv", "wb") as f:
                f.write(private_key)
            full_filename += ".rsa"

        elif algorithm_num == '3':  # Blowfish
            encrypted_data = self.encrypt_blowfish(content, key[:56])
            full_filename += ".bf"

        elif algorithm_num == '4':  # ChaCha20
            encrypted_data = self.encrypt_chacha20(content, key[:32])
            full_filename += ".chacha"

        elif algorithm_num == '5':  # DES
            encrypted_data = self.encrypt_des(content, key[:8])
            full_filename += ".des"

        elif algorithm_num == '6':  # 3DES
            des3_key = key[:24] if len(key) >= 24 else key.ljust(24, b'\0')
            encrypted_data = self.encrypt_3des(content, des3_key)
            full_filename += ".3des"

        elif algorithm_num == '7':  # RC4
            encrypted_data = self.encrypt_rc4(content, key)
            full_filename += ".rc4"

        elif algorithm_num == '8':  # Salsa20
            encrypted_data = self.encrypt_salsa20(content, key[:32])
            full_filename += ".salsa"

        elif algorithm_num == '9':  # MFDG-Hybrid
            encrypted_data, base_key = self.encrypt_mfdg_hybrid(content)
            with open(f"{full_filename}.mfdg", "w") as f:
                json.dump(encrypted_data, f)
            self._save_decryption_key(full_filename, {'base_key': base_key})
            return full_filename + ".mfdg"

        # 保存加密文件
        with open(full_filename, "wb") as f:
            f.write(encrypted_data)

        return full_filename

    def encrypt_file(self, input_file, output_file, algorithm_num, progress_callback=None):
        """加密文件"""
        # 生成随机后缀
        suffix = self.generate_random_suffix()
        base_name = os.path.basename(input_file)
        file_name, file_ext = os.path.splitext(base_name)
        full_filename = f"{file_name}_{suffix}{file_ext}"

        # 使用文件名作为基础密钥
        base_key = file_name.encode()
        key = hashlib.sha512(base_key).digest()

        chunk_size = 64 * 1024  # 64KB chunks

        try:
            with open(input_file, 'rb') as f_in:
                file_size = os.path.getsize(input_file)
                total_chunks = (file_size + chunk_size - 1) // chunk_size

                if algorithm_num == '9':  # MFDG-Hybrid特殊处理
                    # 读取整个文件内容(不适合超大文件)
                    content = f_in.read()
                    encrypted_data, base_key = self.encrypt_mfdg_hybrid(content.decode('utf-8', errors='ignore'))
                    output_file = os.path.join(os.path.dirname(output_file), f"{full_filename}.mfdg")
                    with open(output_file, 'w') as f_out:
                        json.dump(encrypted_data, f_out)
                    self._save_decryption_key(full_filename, {'base_key': base_key})
                    return output_file

                # 其他算法处理
                output_file = os.path.join(os.path.dirname(output_file),
                                           full_filename + self._get_algorithm_extension(algorithm_num))

                with open(output_file, 'wb') as f_out:
                    # 初始化加密器
                    cipher, iv_or_nonce = self._get_cipher_for_algorithm(algorithm_num, key)
                    if iv_or_nonce:
                        f_out.write(iv_or_nonce)  # 写入IV/nonce

                    # 分块加密
                    for chunk_num, chunk in enumerate(self._read_in_chunks(f_in, chunk_size)):
                        if progress_callback:
                            progress_callback(chunk_num / total_chunks * 100)

                        if algorithm_num in ['1', '3', '5', '6']:  # 需要填充的算法
                            chunk = pad(chunk, cipher.block_size)
                        encrypted_chunk = cipher.encrypt(chunk)
                        f_out.write(encrypted_chunk)

            if progress_callback:
                progress_callback(100)

            return output_file
        except Exception as e:
            if os.path.exists(output_file):
                os.remove(output_file)
            raise e

    def decrypt_file(self, input_file, output_file, key=None, progress_callback=None):
        """解密文件"""
        file_name = os.path.basename(input_file)
        base_name, file_ext = os.path.splitext(file_name)

        chunk_size = 64 * 1024  # 64KB chunks

        try:
            with open(input_file, 'rb') as f_in:
                file_size = os.path.getsize(input_file)
                total_chunks = (file_size + chunk_size - 1) // chunk_size

                if file_ext == '.mfdg':
                    # MFDG-Hybrid特殊处理
                    encrypted_data = json.load(f_in)
                    if not key:
                        key = self._load_decryption_key(base_name)
                    decrypted_content = self.decrypt_mfdg_hybrid(encrypted_data, key)
                    with open(output_file, 'w') as f_out:
                        f_out.write(decrypted_content)
                    return output_file

                # 获取凯撒位移
                shift = self.get_shift_from_filename(base_name.split('_')[-1])

                # 应用凯撒密码
                original_name = '_'.join(base_name.split('_')[:-1])
                adjusted_name = self.caesar_cipher(original_name, -shift)

                # 生成密钥
                key = hashlib.sha512(adjusted_name.encode()).digest()

                # 根据扩展名选择解密算法
                algorithm_num = self._get_algorithm_from_extension(file_ext)
                cipher = self._get_cipher_for_algorithm(algorithm_num, key, f_in)

                with open(output_file, 'wb') as f_out:
                    # 分块解密
                    for chunk_num, chunk in enumerate(self._read_in_chunks(f_in, chunk_size)):
                        if progress_callback:
                            progress_callback(chunk_num / total_chunks * 100)

                        decrypted_chunk = cipher.decrypt(chunk)
                        if algorithm_num in ['1', '3', '5', '6']:  # 需要去除填充的算法
                            try:
                                decrypted_chunk = unpad(decrypted_chunk, cipher.block_size)
                            except ValueError:
                                # 最后一块可能不需要处理
                                pass
                        f_out.write(decrypted_chunk)

            if progress_callback:
                progress_callback(100)

            return output_file
        except Exception as e:
            if os.path.exists(output_file):
                os.remove(output_file)
            raise e

    def preview_decrypted_content(self, input_file, key=None):
        """预览解密内容"""
        file_name = os.path.basename(input_file)
        base_name, file_ext = os.path.splitext(file_name)

        try:
            with open(input_file, 'rb') as f_in:
                if file_ext == '.mfdg':
                    # MFDG-Hybrid特殊处理
                    encrypted_data = json.load(f_in)
                    if not key:
                        key = self._load_decryption_key(base_name)
                    decrypted_content = self.decrypt_mfdg_hybrid(encrypted_data, key)
                else:
                    # 其他算法处理
                    encrypted_data = f_in.read()

                    # 获取凯撒位移
                    shift = self.get_shift_from_filename(base_name.split('_')[-1])

                    # 应用凯撒密码
                    original_name = '_'.join(base_name.split('_')[:-1])
                    adjusted_name = self.caesar_cipher(original_name, -shift)

                    # 生成密钥
                    key = hashlib.sha512(adjusted_name.encode()).digest()

                    # 根据扩展名选择解密算法
                    algorithm_num = self._get_algorithm_from_extension(file_ext)

                    if algorithm_num == '1':  # AES
                        decrypted_content = self.decrypt_aes(encrypted_data, key[:32])
                    elif algorithm_num == '3':  # Blowfish
                        decrypted_content = self.decrypt_blowfish(encrypted_data, key[:56])
                    elif algorithm_num == '4':  # ChaCha20
                        decrypted_content = self.decrypt_chacha20(encrypted_data, key[:32])
                    elif algorithm_num == '5':  # DES
                        decrypted_content = self.decrypt_des(encrypted_data, key[:8])
                    elif algorithm_num == '6':  # 3DES
                        des3_key = key[:24] if len(key) >= 24 else key.ljust(24, b'\0')
                        decrypted_content = self.decrypt_3des(encrypted_data, des3_key)
                    elif algorithm_num == '7':  # RC4
                        decrypted_content = self.decrypt_rc4(encrypted_data, key)
                    elif algorithm_num == '8':  # Salsa20
                        decrypted_content = self.decrypt_salsa20(encrypted_data, key[:32])
                    elif algorithm_num == '2':  # RSA
                        priv_key_file = input_file.replace('.rsa', '.priv')
                        if not os.path.exists(priv_key_file):
                            raise FileNotFoundError("未找到RSA私钥文件")
                        with open(priv_key_file, "rb") as f:
                            private_key = f.read()
                        decrypted_content = self.decrypt_rsa(encrypted_data, private_key)
                    else:
                        decrypted_content = "不支持的加密格式"

            # 检查是否是文本内容
            if isinstance(decrypted_content, bytes):
                try:
                    decrypted_content = decrypted_content.decode('utf-8')
                except UnicodeDecodeError:
                    return None, "这是二进制文件，无法预览文本内容"

            if self._is_binary_data(decrypted_content):
                return None, "这是二进制文件，无法预览文本内容"

            return decrypted_content[:1000], None  # 返回前1000个字符

        except Exception as e:
            return None, f"预览失败: {str(e)}"

    def _get_algorithm_extension(self, algorithm_num):
        """获取算法对应的文件扩展名"""
        extensions = {
            '1': '.aes',
            '2': '.rsa',
            '3': '.bf',
            '4': '.chacha',
            '5': '.des',
            '6': '.3des',
            '7': '.rc4',
            '8': '.salsa',
            '9': '.mfdg'
        }
        return extensions.get(algorithm_num, '.enc')

    def _get_algorithm_from_extension(self, extension):
        """从文件扩展名获取算法编号"""
        extensions = {
            '.aes': '1',
            '.rsa': '2',
            '.bf': '3',
            '.chacha': '4',
            '.des': '5',
            '.3des': '6',
            '.rc4': '7',
            '.salsa': '8',
            '.mfdg': '9'
        }
        return extensions.get(extension.lower(), '1')  # 默认使用AES

    def _get_cipher_for_algorithm(self, algorithm_num, key, file_obj=None):
        """根据算法编号获取加密器"""
        if algorithm_num == '1':  # AES
            if file_obj:  # 解密模式
                iv = file_obj.read(AES.block_size)
                return AES.new(key[:32], AES.MODE_CBC, iv=iv)
            else:  # 加密模式
                iv = get_random_bytes(AES.block_size)
                return AES.new(key[:32], AES.MODE_CBC, iv=iv), iv
        elif algorithm_num == '3':  # Blowfish
            if file_obj:
                iv = file_obj.read(Blowfish.block_size)
                return Blowfish.new(key[:56], Blowfish.MODE_CBC, iv=iv)
            else:
                iv = get_random_bytes(Blowfish.block_size)
                return Blowfish.new(key[:56], Blowfish.MODE_CBC, iv=iv), iv
        elif algorithm_num == '4':  # ChaCha20
            if file_obj:
                nonce = file_obj.read(8)
                return ChaCha20.new(key=key[:32], nonce=nonce)
            else:
                nonce = get_random_bytes(8)
                return ChaCha20.new(key=key[:32], nonce=nonce), nonce
        elif algorithm_num == '5':  # DES
            if file_obj:
                iv = file_obj.read(DES.block_size)
                return DES.new(key[:8], DES.MODE_CBC, iv=iv)
            else:
                iv = get_random_bytes(DES.block_size)
                return DES.new(key[:8], DES.MODE_CBC, iv=iv), iv
        elif algorithm_num == '6':  # 3DES
            des3_key = key[:24] if len(key) >= 24 else key.ljust(24, b'\0')
            if file_obj:
                iv = file_obj.read(DES3.block_size)
                return DES3.new(des3_key, DES3.MODE_CBC, iv=iv)
            else:
                iv = get_random_bytes(DES3.block_size)
                return DES3.new(des3_key, DES3.MODE_CBC, iv=iv), iv
        elif algorithm_num == '7':  # RC4
            return RC4.new(key), None
        elif algorithm_num == '8':  # Salsa20
            if file_obj:
                nonce = file_obj.read(8)
                return Salsa20.new(key=key[:32], nonce=nonce)
            else:
                nonce = get_random_bytes(8)
                return Salsa20.new(key=key[:32], nonce=nonce), nonce
        else:  # 默认AES
            if file_obj:
                iv = file_obj.read(AES.block_size)
                return AES.new(key[:32], AES.MODE_CBC, iv=iv)
            else:
                iv = get_random_bytes(AES.block_size)
                return AES.new(key[:32], AES.MODE_CBC, iv=iv), iv

    def _read_in_chunks(self, file_object, chunk_size):
        """生成器函数，分块读取文件"""
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _is_binary_data(self, data):
        """检查数据是否为二进制格式"""
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                return True

        # 检查控制字符(除换行和制表符外)
        if isinstance(data, str):
            for char in data:
                if ord(char) < 32 and char not in ('\n', '\r', '\t'):
                    return True
        return False


class EncryptionApp:
    def __init__(self, root, encryptor):
        self.root = root
        self.encryptor = encryptor
        self.root.title("文件加密解密工具 - 支持大文件处理和预览")
        self.root.geometry("800x700")

        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建选项卡
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 文本加密选项卡
        self.text_encrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.text_encrypt_tab, text="文本加密")
        self._setup_text_encrypt_tab()

        # 文件加密选项卡
        self.file_encrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_encrypt_tab, text="文件加密")
        self._setup_file_encrypt_tab()

        # 解密选项卡
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_tab, text="解密")
        self._setup_decrypt_tab()

        # 关于选项卡
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="关于")
        self._setup_about_tab()

        # 进度条
        self.progress = Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress.pack(pady=10)
        self.progress_label = ttk.Label(self.main_frame, text="")
        self.progress_label.pack()

    def _setup_text_encrypt_tab(self):
        # 文件名输入
        ttk.Label(self.text_encrypt_tab, text="文件名(不含后缀):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.filename_entry = ttk.Entry(self.text_encrypt_tab, width=40)
        self.filename_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        # 文件内容输入
        ttk.Label(self.text_encrypt_tab, text="文件内容:").grid(row=1, column=0, sticky=tk.NW, pady=5)
        self.content_text = scrolledtext.ScrolledText(self.text_encrypt_tab, width=50, height=10)
        self.content_text.grid(row=1, column=1, columnspan=2, pady=5)

        # 加密算法选择
        ttk.Label(self.text_encrypt_tab, text="加密算法:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.algorithm_var = tk.StringVar()
        self.algorithm_combobox = ttk.Combobox(
            self.text_encrypt_tab,
            textvariable=self.algorithm_var,
            values=list(self.encryptor.supported_algorithms.values()),
            state="readonly",
            width=30
        )
        self.algorithm_combobox.current(0)
        self.algorithm_combobox.grid(row=2, column=1, sticky=tk.W, pady=5)

        # 加密按钮
        self.encrypt_button = ttk.Button(
            self.text_encrypt_tab,
            text="加密文本",
            command=self._encrypt_text
        )
        self.encrypt_button.grid(row=3, column=1, pady=10)

    def _setup_file_encrypt_tab(self):
        # 文件选择
        ttk.Label(self.file_encrypt_tab, text="选择要加密的文件:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_file_entry = ttk.Entry(self.file_encrypt_tab, width=50)
        self.input_file_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        self.browse_input_button = ttk.Button(
            self.file_encrypt_tab,
            text="浏览...",
            command=lambda: self._browse_file(self.input_file_entry)
        )
        self.browse_input_button.grid(row=0, column=2, padx=5)

        # 输出文件名
        ttk.Label(self.file_encrypt_tab, text="输出文件名:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_file_entry = ttk.Entry(self.file_encrypt_tab, width=50)
        self.output_file_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        self.browse_output_button = ttk.Button(
            self.file_encrypt_tab,
            text="浏览...",
            command=lambda: self._save_file_dialog(self.output_file_entry)
        )
        self.browse_output_button.grid(row=1, column=2, padx=5)

        # 加密算法选择
        ttk.Label(self.file_encrypt_tab, text="加密算法:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.file_algorithm_var = tk.StringVar()
        self.file_algorithm_combobox = ttk.Combobox(
            self.file_encrypt_tab,
            textvariable=self.file_algorithm_var,
            values=list(self.encryptor.supported_algorithms.values()),
            state="readonly",
            width=30
        )
        self.file_algorithm_combobox.current(0)
        self.file_algorithm_combobox.grid(row=2, column=1, sticky=tk.W, pady=5)

        # 文件信息显示
        self.file_info_label = ttk.Label(self.file_encrypt_tab, text="")
        self.file_info_label.grid(row=3, column=0, columnspan=3, pady=10)

        # 加密按钮
        self.file_encrypt_button = ttk.Button(
            self.file_encrypt_tab,
            text="加密文件",
            command=self._encrypt_file
        )
        self.file_encrypt_button.grid(row=4, column=1, pady=10)

        # 绑定事件
        self.input_file_entry.bind("<FocusOut>", self._update_file_info)

    def _setup_decrypt_tab(self):
        # 加密文件选择
        ttk.Label(self.decrypt_tab, text="选择加密文件:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.encrypted_file_entry = ttk.Entry(self.decrypt_tab, width=50)
        self.encrypted_file_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        self.browse_encrypted_button = ttk.Button(
            self.decrypt_tab,
            text="浏览...",
            command=lambda: self._browse_file(self.encrypted_file_entry,
                                              [("加密文件",
                                                "*.aes *.bf *.chacha *.des *.3des *.rc4 *.salsa *.rsa *.mfdg"),
                                               ("所有文件", "*.*")])
        )
        self.browse_encrypted_button.grid(row=0, column=2, padx=5)

        # 输出文件选择
        ttk.Label(self.decrypt_tab, text="输出文件:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.decrypted_file_entry = ttk.Entry(self.decrypt_tab, width=50)
        self.decrypted_file_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        self.browse_decrypted_button = ttk.Button(
            self.decrypt_tab,
            text="浏览...",
            command=lambda: self._save_file_dialog(self.decrypted_file_entry)
        )
        self.browse_decrypted_button.grid(row=1, column=2, padx=5)

        # 密钥输入(MFDG专用)
        ttk.Label(self.decrypt_tab, text="解密密钥(仅MFDG需要):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(self.decrypt_tab, width=50)
        self.key_entry.grid(row=2, column=1, sticky=tk.W, pady=5)

        # 文件信息显示
        self.encrypted_file_info = ttk.Label(self.decrypt_tab, text="")
        self.encrypted_file_info.grid(row=3, column=0, columnspan=3, pady=10)

        # 预览区域
        ttk.Label(self.decrypt_tab, text="预览(仅文本文件):").grid(row=4, column=0, sticky=tk.NW, pady=5)
        self.preview_text = scrolledtext.ScrolledText(self.decrypt_tab, width=60, height=12, state=tk.DISABLED)
        self.preview_text.grid(row=4, column=1, columnspan=2, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(self.decrypt_tab)
        button_frame.grid(row=5, column=1, pady=10)

        # 预览按钮
        self.preview_button = ttk.Button(
            button_frame,
            text="预览内容",
            command=self._preview_decrypted_content,
            width=15
        )
        self.preview_button.pack(side=tk.LEFT, padx=5)

        # 解密按钮
        self.decrypt_button = ttk.Button(
            button_frame,
            text="解密文件",
            command=self._decrypt_file,
            width=15
        )
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

        # 绑定事件
        self.encrypted_file_entry.bind("<FocusOut>", self._update_encrypted_file_info)

    def _setup_about_tab(self):
        about_text = """
        文件加密解密工具

        版本: 2.1
        作者: 火杯/deepseek(感谢你伟大的AI之神)

        功能:
        - 支持多种加密算法
        - 文本加密和解密
        - 文件加密和解密(支持大文件)
        - 解密内容预览功能
        - 安全密钥存储

        使用方法:
        1. 在"文本加密"选项卡中加密文本内容
        2. 在"文件加密"选项卡中加密文件
        3. 在"解密"选项卡中预览或解密文件

        注意: 请妥善保管您的密钥文件!
        """
        ttk.Label(self.about_tab, text=about_text, justify=tk.LEFT).pack(padx=10, pady=10, anchor=tk.W)

    def _update_progress(self, value):
        """更新进度条"""
        self.progress['value'] = value
        self.progress_label.config(text=f"处理进度: {int(value)}%")
        self.root.update_idletasks()

    def _encrypt_text(self):
        filename = self.filename_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        algorithm_name = self.algorithm_var.get()

        if not filename or not content:
            messagebox.showerror("错误", "文件名和内容不能为空!")
            return

        # 获取算法编号
        algorithm_num = None
        for num, name in self.encryptor.supported_algorithms.items():
            if name == algorithm_name:
                algorithm_num = num
                break

        try:
            self._update_progress(0)
            encrypted_filename = self.encryptor.encrypt_file_gui(filename, content, algorithm_num)
            self._update_progress(100)
            messagebox.showinfo("成功", f"文本加密成功!\n算法: {algorithm_name}\n文件名: {encrypted_filename}")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
        finally:
            self._update_progress(0)

    def _encrypt_file(self):
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        algorithm_name = self.file_algorithm_var.get()

        if not input_file or not output_file:
            messagebox.showerror("错误", "请选择输入文件和输出文件!")
            return

        # 获取算法编号
        algorithm_num = None
        for num, name in self.encryptor.supported_algorithms.items():
            if name == algorithm_name:
                algorithm_num = num
                break

        try:
            self._update_progress(0)
            encrypted_file = self.encryptor.encrypt_file(
                input_file,
                output_file,
                algorithm_num,
                progress_callback=self._update_progress
            )
            messagebox.showinfo("成功", f"文件加密成功!\n加密文件: {encrypted_file}")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
        finally:
            self._update_progress(0)

    def _decrypt_file(self):
        encrypted_file = self.encrypted_file_entry.get()
        output_file = self.decrypted_file_entry.get()
        key = self.key_entry.get()

        if not encrypted_file or not output_file:
            messagebox.showerror("错误", "请选择加密文件和输出文件!")
            return

        try:
            self._update_progress(0)
            decrypted_file = self.encryptor.decrypt_file(
                encrypted_file,
                output_file,
                key,
                progress_callback=self._update_progress
            )
            messagebox.showinfo("成功", f"文件解密成功!\n解密文件: {decrypted_file}")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
        finally:
            self._update_progress(0)

    def _preview_decrypted_content(self):
        """预览解密内容"""
        encrypted_file = self.encrypted_file_entry.get()
        key = self.key_entry.get()

        if not encrypted_file:
            messagebox.showerror("错误", "请选择加密文件!")
            return

        if not os.path.exists(encrypted_file):
            messagebox.showerror("错误", "文件不存在!")
            return

        try:
            self._update_progress(0)
            decrypted_content, error = self.encryptor.preview_decrypted_content(encrypted_file, key)
            self._update_progress(100)

            self.preview_text.config(state=tk.NORMAL)
            self.preview_text.delete("1.0", tk.END)

            if error:
                self.preview_text.insert(tk.END, error)
            else:
                self.preview_text.insert(tk.END, decrypted_content)
                if len(decrypted_content) >= 1000:
                    self.preview_text.insert(tk.END, "\n\n... (内容已截断，完整内容将在解密后显示)")

            self.preview_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("预览错误", f"无法预览内容: {str(e)}")
        finally:
            self._update_progress(0)

    def _browse_file(self, entry_widget, filetypes=None):
        """打开文件选择对话框"""
        if filetypes is None:
            filetypes = [("所有文件", "*.*")]

        filepath = filedialog.askopenfilename(filetypes=filetypes)
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)
            self.root.event_generate("<FocusOut>")  # 触发更新文件信息

    def _save_file_dialog(self, entry_widget):
        """打开文件保存对话框"""
        filepath = filedialog.asksaveasfilename(defaultextension=".enc")
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)

    def _update_file_info(self, event=None):
        """更新文件信息显示"""
        filepath = self.input_file_entry.get()
        if filepath and os.path.exists(filepath):
            size = os.path.getsize(filepath)
            size_str = self._format_file_size(size)
            self.file_info_label.config(text=f"文件大小: {size_str}")
        else:
            self.file_info_label.config(text="")

    def _update_encrypted_file_info(self, event=None):
        """更新加密文件信息显示"""
        filepath = self.encrypted_file_entry.get()
        if filepath and os.path.exists(filepath):
            size = os.path.getsize(filepath)
            size_str = self._format_file_size(size)
            algorithm = self._detect_algorithm_from_filename(filepath)
            self.encrypted_file_info.config(text=f"文件大小: {size_str} | 算法: {algorithm}")
        else:
            self.encrypted_file_info.config(text="")

    def _detect_algorithm_from_filename(self, filename):
        """从文件名检测加密算法"""
        ext = os.path.splitext(filename)[1].lower()
        algorithms = {
            '.aes': 'AES-256-CBC',
            '.rsa': 'RSA-4096',
            '.bf': 'Blowfish',
            '.chacha': 'ChaCha20',
            '.des': 'DES',
            '.3des': '3DES',
            '.rc4': 'RC4',
            '.salsa': 'Salsa20',
            '.mfdg': 'MFDG-Hybrid'
        }
        return algorithms.get(ext, "未知算法")

    def _format_file_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"


if __name__ == "__main__":
    root = tk.Tk()
    encryptor = TraditionalEncryptor()
    app = EncryptionApp(root, encryptor)
    root.mainloop()
