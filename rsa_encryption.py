import random
import math
from Crypto.PublicKey import RSA as CryptoRSA

class RSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.p = self._generate_prime(key_size // 2)
        self.q = self._generate_prime(key_size // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = self._choose_public_exponent()
        self.d = self._modular_inverse(self.e, self.phi)
        
    def _is_prime(self, n, k=5):
        """Miller-Rabin素性测试"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
            
        # 将n-1表示为2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # 进行k次测试
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
        
    def _generate_prime(self, bits):
        """生成指定位数的素数"""
        while True:
            # 生成随机奇数
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            if self._is_prime(n):
                return n
                
    def _choose_public_exponent(self):
        """选择公钥指数e"""
        e = 65537  # 常用值
        while math.gcd(e, self.phi) != 1:
            e = random.randint(3, self.phi - 1)
        return e
        
    def _modular_inverse(self, a, m):
        """计算模逆"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
            
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise Exception("模逆不存在")
        return x % m
        
    def get_public_key(self):
        """获取公钥"""
        return (self.e, self.n)
        
    def get_private_key(self):
        """获取私钥"""
        return (self.d, self.n)
        
    def encrypt(self, message):
        """加密消息"""
        e, n = self.get_public_key()
        # 将消息转换为整数
        m = int.from_bytes(message, 'big')
        # 加密
        c = pow(m, e, n)
        # 将密文转换回字节
        return c.to_bytes((c.bit_length() + 7) // 8, 'big')
        
    def decrypt(self, ciphertext):
        """解密消息"""
        d, n = self.get_private_key()
        # 将密文转换为整数
        c = int.from_bytes(ciphertext, 'big')
        # 解密
        m = pow(c, d, n)
        # 将明文转换回字节
        return m.to_bytes((m.bit_length() + 7) // 8, 'big')
        
    def sign(self, message):
        """数字签名"""
        d, n = self.get_private_key()
        # 计算消息哈希
        h = int.from_bytes(message, 'big')
        # 签名
        s = pow(h, d, n)
        # 将签名转换回字节
        return s.to_bytes((s.bit_length() + 7) // 8, 'big')
        
    def verify(self, message, signature):
        """验证签名"""
        e, n = self.get_public_key()
        # 计算消息哈希
        h = int.from_bytes(message, 'big')
        # 验证签名
        s = int.from_bytes(signature, 'big')
        v = pow(s, e, n)
        return h == v 

    def set_public_key(self, e, n):
        """设置公钥"""
        self.e = e
        self.n = n

    def set_private_key(self, d, n):
        """设置私钥"""
        self.d = d
        self.n = n 

    def set_public_key_from_pem(self, pem_data):
        """
        从PEM格式的公钥内容设置公钥 (pem_data可以是str或bytes)
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
        key = CryptoRSA.import_key(pem_data)
        self.e = key.e
        self.n = key.n

    @staticmethod
    def get_e_n_from_pem(pem_data):
        if isinstance(pem_data, bytes):
            key = CryptoRSA.import_key(pem_data)
        else:
            key = CryptoRSA.import_key(pem_data.encode())
        return key.e, key.n 