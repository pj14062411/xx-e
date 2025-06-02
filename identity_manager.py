import os
import json
import uuid
import hashlib
from datetime import datetime # --- FIXED --- Added datetime import

# Cryptography 库导入，用于密钥生成和私钥加密
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption, PrivateFormat, load_pem_public_key, load_pem_private_key 


# PyQt5 导入，用于 UI 交互 (QInputDialog, QMessageBox)
from PyQt5.QtWidgets import QInputDialog, QMessageBox, QLineEdit, QFileDialog

# 导入你的 RSA 类
from rsa_encryption import RSA 

class IdentityManager:
    CONFIG_FILE = 'config.json'
    IDENTITY_KEYS_FILE = 'my_identity_keys.json'
    TRUSTED_PEERS_FILE = 'trusted_peers.json' # --- NEW --- 信任伙伴文件

    def __init__(self, parent_window, rsa_instance):
        """
        初始化身份管理器。
        :param parent_window: PyQt5 主窗口实例，用于 QInputDialog 和 QMessageBox 的父窗口。
        :param rsa_instance: 应用程序的 RSA 实例，用于设置公钥和私钥。
        """
        self.parent_window = parent_window
        self.rsa = rsa_instance # 接收外部的 RSA 实例
        
        self.my_uuid = None
        self.my_nickname = None
        self._my_public_key_pem = None # 存储 PEM 格式的公钥字节串，用于指纹计算

        self.trusted_peers = {} # --- NEW --- 存储已信任的邻居公钥，键为 UUID
        self.load_trusted_peers() # --- NEW --- 加载信任伙伴

    def load_or_create_identity(self):
        """
        从 config.json 加载用户 UUID 和昵称，如果不存在则生成并保存。
        """
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.my_uuid = config.get('uuid')
                self.my_nickname = config.get('nickname')
                if not self.my_uuid or not self.my_nickname:
                    raise ValueError("配置文件内容不完整")
                print(f"DEBUG: 加载身份: UUID={self.my_uuid}, 昵称={self.my_nickname}")
            except (json.JSONDecodeError, ValueError) as e:
                QMessageBox.warning(self.parent_window, "配置加载错误", f"无法读取或解析 {self.CONFIG_FILE}: {e}\n将重新生成身份。")
                self._create_new_identity()
        else:
            self._create_new_identity()

    def _create_new_identity(self):
        """
        生成新的 UUID 和昵称，并保存到 config.json。
        """
        self.my_uuid = str(uuid.uuid4())
        print("DEBUG: 准备弹出昵称输入框...") 
        nickname, ok = QInputDialog.getText(self.parent_window, "设置用户昵称", "请输入您的用户昵称 (用于P2P发现):", QLineEdit.Normal, "新用户")
        print("DEBUG: 昵称输入框已关闭。") 
        if ok and nickname:
            self.my_nickname = nickname
        else:
            self.my_nickname = "新用户" # 默认昵称
        
        config = {'uuid': self.my_uuid, 'nickname': self.my_nickname}
        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            print(f"DEBUG: 生成并保存新身份: UUID={self.my_uuid}, 昵称={self.my_nickname}")
        except Exception as e:
            QMessageBox.critical(self.parent_window, "保存配置错误", f"无法保存身份到 {self.CONFIG_FILE}: {e}")

    def load_or_create_rsa_identity_keys(self):
        """
        从 my_identity_keys.json 加载 RSA 密钥对，如果不存在则生成并保存。
        私钥将使用密码加密存储。
        """
        if os.path.exists(self.IDENTITY_KEYS_FILE):
            print("DEBUG: 密钥文件存在，尝试加载密钥。") 
            try:
                with open(self.IDENTITY_KEYS_FILE, 'r', encoding='utf-8') as f:
                    key_data = json.load(f)
                
                # 尝试加载公钥
                e_val = int(key_data['public_exponent'], 16)
                n_val = int(key_data['modulus'], 16)
                self.rsa.set_public_key(e_val, n_val)
                self._my_public_key_pem = key_data['public_key_pem'].encode('utf-8') # 存储 PEM 字节串用于指纹

                # 尝试解密并加载私钥
                print("DEBUG: 准备弹出密钥密码输入框 (加载密钥)...") 
                password, ok = QInputDialog.getText(self.parent_window, "输入密钥密码", "请输入您的密钥密码 (用于解密私钥):", QLineEdit.Password)
                if not ok:
                    QMessageBox.warning(self.parent_window, "操作取消", "未输入密码，私钥未加载。部分功能可能受限。")
                    return

                # 只有当 key_data 中包含加密的私钥指数时才尝试解密
                if 'encrypted_private_exponent' in key_data and 'salt' in key_data and 'iv' in key_data:
                    encrypted_d_hex = key_data['encrypted_private_exponent']
                    salt_hex = key_data['salt']
                    iv_hex = key_data['iv']
                    decrypted_d_bytes = self._decrypt_private_key_exponent(
                        password.encode('utf-8'),
                        bytes.fromhex(encrypted_d_hex),
                        bytes.fromhex(salt_hex),
                        bytes.fromhex(iv_hex)
                    )
                    d_val = int(decrypted_d_bytes.hex(), 16) # 解密后的 d 也是十六进制字符串，转为 int
                    self.rsa.set_private_key(d_val, n_val)
                    QMessageBox.information(self.parent_window, "密钥加载成功", "RSA 密钥对已成功加载。")
                    print("DEBUG: RSA 密钥对已加载。")
                else:
                    QMessageBox.warning(self.parent_window, "密钥格式错误", "密钥文件缺少加密的私钥指数信息。")
                    print("DEBUG: 密钥文件缺少加密的私钥指数信息。")
                    self._create_new_rsa_identity_keys() # 尝试重新生成

            except (json.JSONDecodeError, ValueError, TypeError) as e:
                QMessageBox.critical(self.parent_window, "密钥加载错误", f"无法读取或解析 {self.IDENTITY_KEYS_FILE} 或密码错误: {e}\n将尝试重新生成密钥对。")
                print(f"DEBUG: 密钥加载/解析错误: {e}") 
                self._create_new_rsa_identity_keys()
            except Exception as e:
                QMessageBox.critical(self.parent_window, "密钥加载错误", f"加载密钥时发生未知错误: {e}\n将尝试重新生成密钥对。")
                print(f"DEBUG: 密钥加载未知错误: {e}") 
                self._create_new_rsa_identity_keys()
        else:
            print("DEBUG: 密钥文件不存在，准备创建新密钥。") 
            self._create_new_rsa_identity_keys()

    def _create_new_rsa_identity_keys(self):
        """
        生成新的 RSA 密钥对，并使用密码加密私钥后保存。
        """
        print("DEBUG: 准备弹出密钥密码输入框 (创建密钥)...") 
        password, ok = QInputDialog.getText(self.parent_window, "设置密钥密码", "请为您的新密钥设置一个密码 (用于加密私钥):", QLineEdit.Password)
        if not ok or not password:
            QMessageBox.warning(self.parent_window, "操作取消", "未设置密码，密钥对未生成。部分功能可能受限。")
            return

        # 生成 RSA 密钥对 (使用 cryptography 库)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, # 2048 位密钥大小
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # 提取 e, d, n
        e_val = public_key.public_numbers().e
        n_val = public_key.public_numbers().n
        d_val = private_key.private_numbers().d

        # 将 d 值转换为字节串进行加密 (通常 d 很大，需要足够字节表示)
        d_bytes = d_val.to_bytes((d_val.bit_length() + 7) // 8, 'big')

        # 加密私钥指数 d
        encrypted_d_bytes, salt, iv = self._encrypt_private_key_exponent(password.encode('utf-8'), d_bytes)

        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        self._my_public_key_pem = public_key_pem # 存储 PEM 字节串用于指纹

        # 保存密钥信息到 JSON 文件
        key_data = {
            'public_exponent': hex(e_val),
            'modulus': hex(n_val),
            'encrypted_private_exponent': encrypted_d_bytes.hex(), # 加密后的 d 存储为十六进制字符串
            'salt': salt.hex(),
            'iv': iv.hex(),
            'public_key_pem': public_key_pem.decode('utf-8') # PEM 存储为字符串
        }
        try:
            with open(self.IDENTITY_KEYS_FILE, 'w', encoding='utf-8') as f:
                json.dump(key_data, f, indent=4, ensure_ascii=False)
            QMessageBox.information(self.parent_window, "密钥生成成功", "已生成并保存新的 RSA 密钥对。")
            print("DEBUG: 新的 RSA 密钥对已生成并保存。")
            # 设置 self.rsa 实例的密钥
            self.rsa.set_public_key(e_val, n_val)
            self.rsa.set_private_key(d_val, n_val) # 内存中直接使用解密后的 d
        except Exception as e:
            QMessageBox.critical(self.parent_window, "保存密钥错误", f"无法保存密钥到 {self.IDENTITY_KEYS_FILE}: {e}")

    def _encrypt_private_key_exponent(self, password_bytes, d_bytes):
        """
        使用密码加密私钥指数 d。
        """
        salt = os.urandom(16) # 随机盐
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 密钥长度 (AES256)
            salt=salt,
            iterations=100000, # 迭代次数，增加安全性
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)

        iv = os.urandom(16) # 随机 IV
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # PKCS7 填充
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_d_bytes = padder.update(d_bytes) + padder.finalize()

        encrypted_d = encryptor.update(padded_d_bytes) + encryptor.finalize()
        return encrypted_d, salt, iv

    def _decrypt_private_key_exponent(self, password_bytes, encrypted_d_bytes, salt, iv):
        """
        使用密码解密私钥指数 d。
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 密钥长度 (AES256)
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_padded_d = decryptor.update(encrypted_d_bytes) + decryptor.finalize()

        # PKCS7 去填充
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_d = unpadder.update(decrypted_padded_d) + unpadder.finalize()
        return decrypted_d

    def get_my_public_key_fingerprint(self):
        """
        获取本机身份公钥的 SHA256 指纹（十六进制字符串）。
        """
        if self._my_public_key_pem is not None: 
            hasher = hashlib.sha256()
            hasher.update(self._my_public_key_pem)
            return hasher.hexdigest()
        return "无法获取公钥指纹"

    def get_my_public_key_pem(self):
        """
        获取本机身份公钥的 PEM 格式字节串。
        """
        return self._my_public_key_pem

    # --- NEW --- 信任伙伴管理
    def load_trusted_peers(self):
        """
        从 trusted_peers.json 加载已信任的伙伴公钥。
        """
        if os.path.exists(self.TRUSTED_PEERS_FILE):
            try:
                with open(self.TRUSTED_PEERS_FILE, 'r', encoding='utf-8') as f:
                    self.trusted_peers = json.load(f)
                print(f"DEBUG: 已加载 {len(self.trusted_peers)} 个信任伙伴。")
            except json.JSONDecodeError as e:
                QMessageBox.warning(self.parent_window, "信任伙伴加载错误", f"无法解析 {self.TRUSTED_PEERS_FILE}: {e}\n将清空信任伙伴列表。")
                self.trusted_peers = {}
            except Exception as e:
                QMessageBox.warning(self.parent_window, "信任伙伴加载错误", f"加载 {self.TRUSTED_PEERS_FILE} 时发生错误: {e}\n将清空信任伙伴列表。")
                self.trusted_peers = {}
        else:
            self.trusted_peers = {}
            print("DEBUG: 未找到信任伙伴文件，信任列表为空。")

    def save_trusted_peers(self):
        """
        保存已信任的伙伴公钥到 trusted_peers.json。
        """
        try:
            with open(self.TRUSTED_PEERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.trusted_peers, f, indent=4, ensure_ascii=False)
            print(f"DEBUG: 已保存 {len(self.trusted_peers)} 个信任伙伴。")
        except Exception as e:
            QMessageBox.critical(self.parent_window, "保存信任伙伴错误", f"无法保存信任伙伴到 {self.TRUSTED_PEERS_FILE}: {e}")

    def add_trusted_peer(self, peer_uuid, nickname, public_key_pem_str):
        """
        添加一个信任伙伴到列表并保存。
        """
        self.trusted_peers[peer_uuid] = {
            'nickname': nickname,
            'public_key_pem': public_key_pem_str,
            'trusted_at': datetime.now().isoformat() # 记录信任时间
        }
        self.save_trusted_peers()

    def is_peer_trusted(self, peer_uuid):
        """
        检查一个伙伴是否已被信任。
        """
        return peer_uuid in self.trusted_peers

    def get_trusted_peer_pubkey_pem(self, peer_uuid):
        """
        获取一个信任伙伴的公钥 PEM 字节串。
        """
        peer_data = self.trusted_peers.get(peer_uuid)
        if peer_data:
            return peer_data.get('public_key_pem').encode('utf-8') # 返回 PEM 字节串
        return None

    def get_fingerprint_from_pem(self, public_key_pem_bytes):
        """
        从 PEM 格式公钥字节串计算指纹。
        """
        if public_key_pem_bytes:
            hasher = hashlib.sha256()
            hasher.update(public_key_pem_bytes)
            return hasher.hexdigest()
        return "无效指纹"

    def export_private_key_to_file(self):
        """
        导出私钥到文件。
        """
        try:
            file_name, _ = QFileDialog.getSaveFileName(self.parent_window, "导出私钥", "", "私钥文件 (*.priv)")
            if file_name:
                password, ok = QInputDialog.getText(self.parent_window, "输入密钥密码", "请输入您的密钥密码 (用于解密私钥以便导出):", QLineEdit.Password)
                if not ok or not password:
                    QMessageBox.warning(self.parent_window, "操作取消", "未输入密码，私钥未导出。")
                    return

                private_key_obj = None
                if os.path.exists(self.IDENTITY_KEYS_FILE):
                    with open(self.IDENTITY_KEYS_FILE, 'r', encoding='utf-8') as f:
                        key_data = json.load(f)
                    
                    if 'private_key_pem_encrypted' in key_data: 
                        encrypted_pem = key_data['private_key_pem_encrypted'].encode('utf-8')
                        try:
                            private_key_obj = load_pem_private_key(encrypted_pem, password.encode('utf-8'), backend=default_backend())
                        except Exception as e:
                            QMessageBox.critical(self.parent_window, "解密失败", f"密码错误或解密私钥失败: {e}")
                            return
                    else: 
                        QMessageBox.warning(self.parent_window, "警告", "密钥文件格式不支持直接导出加密的PEM私钥，或私钥未加密。")
                        return
                else:
                    QMessageBox.warning(self.parent_window, "警告", "没有找到身份密钥文件。")
                    return
                

                if private_key_obj:
                    exported_pem = private_key_obj.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption() 
                    )
                    with open(file_name, 'wb') as f:
                        f.write(exported_pem)
                    QMessageBox.information(self.parent_window, "成功", "私钥导出成功 (未加密 PEM)。")
                else:
                    QMessageBox.warning(self.parent_window, "警告", "无法获取私钥对象进行导出。")
        except Exception as e:
            QMessageBox.critical(self.parent_window, "错误", f"导出私钥失败: {str(e)}")

    def import_public_key_from_file(self):
        """
        从文件导入公钥，并设置到 RSA 实例中。
        """
        try:
            file_name, _ = QFileDialog.getOpenFileName(self.parent_window, "导入公钥", "", "公钥文件 (*.pub)")
            if file_name:
                with open(file_name, 'rb') as f:
                    public_pem = f.read()
                public_key_obj = load_pem_public_key(public_pem, backend=default_backend())
                e_val = public_key_obj.public_numbers().e
                n_val = public_key_obj.public_numbers().n
                self.rsa.set_public_key(e_val, n_val)
                self._my_public_key_pem = public_pem 
                QMessageBox.information(self.parent_window, "成功", "公钥导入成功")
        except Exception as e:
            QMessageBox.critical(self.parent_window, "错误", f"导入公钥失败: {str(e)}")

    def import_private_key_from_file(self):
        """
        从文件导入私钥，并设置到 RSA 实例中。
        """
        try:
            file_name, _ = QFileDialog.getSaveFileName(self.parent_window, "导入私钥", "", "私钥文件 (*.priv)")
            if file_name:
                password, ok = QInputDialog.getText(self.parent_window, "输入密钥密码", "请输入导入私钥的密码 (如果私钥已加密):", QLineEdit.Password)
                if not ok:
                    QMessageBox.warning(self.parent_window, "操作取消", "未输入密码，私钥未导入。")
                    return

                with open(file_name, 'rb') as f: 
                    private_pem = f.read()
                
                private_key_obj = load_pem_private_key(private_pem, password.encode('utf-8') if password else None, backend=default_backend())
                
                d_val = private_key_obj.private_numbers().d
                n_val = private_key_obj.private_numbers().n
                self.rsa.set_private_key(d_val, n_val)
                
                public_key_obj = private_key_obj.public_key()
                self._my_public_key_pem = public_key_obj.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
                QMessageBox.information(self.parent_window, "成功", "私钥导入成功。")
        except Exception as e:
            QMessageBox.critical(self.parent_window, "错误", f"导入私钥失败: {str(e)}")

