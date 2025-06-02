import socket
import json 
import time 
import struct 
import threading 
from PyQt5.QtCore import QThread, pyqtSignal 

# Cryptography 库导入，用于公钥 PEM 解析
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend

# P2P 发现相关常量
UDP_DISCOVERY_PORT = 55000  # 用于 P2P 发现的 UDP 端口
BROADCAST_ADDRESS = '10.136.15.255'#'255.255.255.255'  IPv4 广播地址
BROADCAST_INTERVAL_S = 5    # 每隔多少秒发送一次广播
PEER_TIMEOUT_S = BROADCAST_INTERVAL_S * 3.5 # 超过多少秒未收到广播则认为邻居离线

# P2P 协议消息类型
MSG_TYPE_KEY_EXCHANGE = "key_exchange"
MSG_TYPE_FILE_TRANSFER = "file_transfer"

# 仅使用标准 socket 模块获取本地 IP 地址
def get_suggested_local_ip():
    """
    使用标准 socket 模块尝试获取一个非环回的本地 IPv4 地址。
    通过尝试连接到一个外部地址（不实际发送数据）来确定出站接口的 IP。
    如果失败，则返回 '127.0.0.1' 作为后备。
    """
    s = None
    ip = '127.0.0.1' 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1) 
        s.connect(('8.8.8.8', 80)) 
        ip = s.getsockname()[0] 
    except Exception:
        try:
            hostname = socket.gethostname()
            ip_from_hostname = socket.gethostbyname(hostname)
            if not ip_from_hostname.startswith("127.") and ip.startswith("127."):
                ip = ip_from_hostname
        except socket.gaierror: 
            pass 
    finally:
        if s:
            s.close()
    return ip

class P2PConnectionThread(QThread):
    """
    P2P 连接线程：处理单个 P2P 会话的 TCP 数据传输和公钥交换。
    可以作为客户端发起连接，也可以接受一个已建立的连接。
    """
    message_received = pyqtSignal(str, str) # 消息内容 (str), 对方 UUID (str)
    key_exchange_completed = pyqtSignal(str, str) # 对方 UUID (str), 状态信息 (str)
    peer_disconnected = pyqtSignal(str) # 对方 UUID (str)
    connection_status_update = pyqtSignal(str) # 仅用于内部调试或更细粒度的 UI 更新

    # TOFU 验证请求信号和内部事件/结果
    request_tofu_verification = pyqtSignal(dict, QThread) # 包含 peer_info 和此线程实例自身
    
    def __init__(self, my_uuid, my_nickname, my_pk_fingerprint, rsa_instance, identity_manager,
                 socket_obj=None, peer_ip=None, peer_port=None, parent=None):
        super().__init__(parent)
        self.my_uuid = my_uuid
        self.my_nickname = my_nickname
        self.my_pk_fingerprint = my_pk_fingerprint
        self.rsa = rsa_instance # 应用程序的 RSA 实例
        self.identity_manager = identity_manager # 身份管理器实例

        self.data_socket = socket_obj # 如果是服务器接受的连接，直接传入 socket
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        
        self.running = True
        self.peer_uuid = None # 对方的 UUID，在密钥交换后确定
        self.peer_nickname = None # 对方的昵称
        self.peer_public_key_pem = None # 对方的公钥 PEM 格式

        self.is_connected = False # 连接状态标志

        # TOFU 验证相关
        self.tofu_event = threading.Event() # 用于等待主线程的 TOFU 结果
        self.tofu_result = False # 存储 TOFU 验证结果 (True: 信任, False: 拒绝)

    def _recv_all(self, n_bytes):
        buffer = b''
        while len(buffer) < n_bytes:
            if not self.running or not self.data_socket: 
                return None
            try:
                # --- MODIFIED --- 移除了内部的 settimeout，依赖外部设置的超时
                chunk = self.data_socket.recv(n_bytes - len(buffer))
            except socket.timeout: 
                continue 
            except OSError as e: 
                print(f"ERROR: P2PConnectionThread OSError during recv: {e}")
                return None 
            if not chunk: 
                print(f"DEBUG: P2PConnectionThread 收到空数据，连接可能已关闭。")
                return None
            buffer += chunk
        return buffer

    def run(self):
        try:
            if not self.data_socket: # 如果是作为客户端发起连接
                self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print(f"DEBUG: P2PConnectionThread 尝试连接到 {self.peer_ip}:{self.peer_port}")
                self.data_socket.connect((self.peer_ip, self.peer_port)) 
                self.connection_status_update.emit(f"已连接到 {self.peer_ip}:{self.peer_port}")
            else: # 如果是作为服务器接受的连接
                print(f"DEBUG: P2PConnectionThread 已接受来自 {self.peer_ip}:{self.peer_port} 的连接。")
                self.connection_status_update.emit(f"接受来自 {self.peer_ip}:{self.peer_port} 的连接")

            # --- NEW --- 设置套接字超时，以适应用户交互时间
            self.data_socket.settimeout(60.0) # 延长超时至 60 秒

            self.is_connected = True 
            print(f"DEBUG: P2PConnectionThread {self.my_uuid[:8]} is_connected set to True. Peer: {self.peer_ip}:{self.peer_port}")
            
            try:
                self._perform_key_exchange()
                print(f"DEBUG: P2PConnectionThread {self.my_uuid[:8]} finished key exchange successfully.")
            except Exception as ke_e:
                print(f"ERROR: P2PConnectionThread {self.my_uuid[:8]} key exchange failed: {ke_e}")
                self.is_connected = False 
                self.running = False 
                self.key_exchange_completed.emit(self.peer_uuid if self.peer_uuid else f"unidentified_peer_{self.peer_ip}:{self.peer_port}", f"密钥交换失败: {ke_e}")
                return 

            # 接收数据循环
            while self.running and self.data_socket and self.is_connected: 
                len_prefix_bytes = self._recv_all(4) 
                if len_prefix_bytes is None:
                    print(f"DEBUG: P2PConnectionThread {self.my_uuid[:8]} recv_all returned None, breaking loop.")
                    break 
                
                msg_len = struct.unpack('>I', len_prefix_bytes)[0]
                if msg_len == 0: 
                    continue

                message_bytes = self._recv_all(msg_len)
                if message_bytes is None:
                    break 
                
                try:
                    self.message_received.emit(message_bytes.decode('utf-8'), self.peer_uuid)
                except UnicodeDecodeError as ude:
                    print(f"ERROR: 消息解码失败: {ude}")
                    break 
        
        except socket.timeout as e:
            print(f"ERROR: P2PConnectionThread 网络操作超时: {repr(e)}")
        except OSError as e: 
            print(f"ERROR: P2PConnectionThread 网络错误: {repr(e)}")
        except Exception as e:
            print(f"ERROR: P2PConnectionThread 未知错误: {repr(e)}")
        finally:
            self.running = False 
            self.is_connected = False 
            if self.data_socket:
                try: self.data_socket.shutdown(socket.SHUT_RDWR) 
                except OSError: pass 
                try: self.data_socket.close()
                except OSError: pass
                self.data_socket = None
            
            if self.peer_uuid:
                self.peer_disconnected.emit(self.peer_uuid)
            else: 
                self.peer_disconnected.emit(f"unidentified_peer_{self.peer_ip}:{self.peer_port}")


    def _perform_key_exchange(self):
        """
        执行公钥交换协议。
        """
        print(f"DEBUG: 开始与 {self.peer_ip}:{self.peer_port} 进行公钥交换...")
        
        # 1. 构造并发送自己的公钥信息
        my_public_key_pem = self.identity_manager.get_my_public_key_pem()
        if not my_public_key_pem:
            raise Exception("本机公钥未加载，无法进行公钥交换。")

        key_exchange_msg = {
            'type': MSG_TYPE_KEY_EXCHANGE,
            'sender_uuid': self.my_uuid,
            'sender_nickname': self.my_nickname,
            'sender_pk_fingerprint': self.my_pk_fingerprint,
            'sender_public_key_pem': my_public_key_pem.decode('utf-8')
        }
        self.send_data_to_peer(json.dumps(key_exchange_msg).encode('utf-8'))
        print("DEBUG: 已发送本机公钥信息。")

        # 2. 接收对方的公钥信息
        len_prefix_bytes = self._recv_all(4)
        if len_prefix_bytes is None: raise Exception("公钥交换失败：未收到对方长度前缀。")
        msg_len = struct.unpack('>I', len_prefix_bytes)[0]
        peer_key_exchange_bytes = self._recv_all(msg_len)
        if peer_key_exchange_bytes is None: raise Exception("公钥交换失败：未收到对方公钥数据。")

        peer_key_exchange_msg = json.loads(peer_key_exchange_bytes.decode('utf-8'))
        
        # 验证消息类型
        if peer_key_exchange_msg.get('type') != MSG_TYPE_KEY_EXCHANGE:
            raise Exception("公钥交换失败：收到非公钥交换消息。")

        # 提取对方信息
        self.peer_uuid = peer_key_exchange_msg.get('sender_uuid')
        self.peer_nickname = peer_key_exchange_msg.get('sender_nickname')
        self.peer_public_key_pem = peer_key_exchange_msg.get('sender_public_key_pem').encode('utf-8')
        peer_fingerprint = peer_key_exchange_msg.get('sender_pk_fingerprint')

        if not self.peer_uuid or not self.peer_public_key_pem:
            raise Exception("公钥交换失败：对方信息不完整。")

        print(f"DEBUG: 已收到 {self.peer_nickname} ({self.peer_uuid[:8]}) 的公钥信息。")

        # 3. 首次使用信任 (TOFU) 验证
        if not self.identity_manager.is_peer_trusted(self.peer_uuid):
            print(f"DEBUG: 邻居 {self.peer_nickname} ({self.peer_uuid[:8]}) 未被信任，请求 TOFU 验证。")
            
            # 检查公钥指纹是否匹配 (如果之前已经连接过但未信任)
            existing_trusted_pem = self.identity_manager.get_trusted_peer_pubkey_pem(self.peer_uuid)
            if existing_trusted_pem and existing_trusted_pem != self.peer_public_key_pem:
                raise Exception(f"安全警告：与 {self.peer_nickname} 的公钥指纹不匹配！\n"
                                f"旧指纹: {self.identity_manager.get_fingerprint_from_pem(existing_trusted_pem)[:16]}...\n"
                                f"新指纹: {peer_fingerprint[:16]}...\n"
                                f"这可能意味着中间人攻击！连接将被断开。")

            # 通过信号通知主线程弹出 TOFU 对话框
            tofu_info = {
                'peer_uuid': self.peer_uuid,
                'nickname': self.peer_nickname,
                'fingerprint': peer_fingerprint,
                'public_key_pem': self.peer_public_key_pem.decode('utf-8') 
            }
            self.tofu_event.clear() 
            self.request_tofu_verification.emit(tofu_info, self) 
            
            # 等待主线程的 TOFU 验证结果
            print(f"DEBUG: P2PConnectionThread 等待 TOFU 验证结果...")
            if not self.tofu_event.wait(60): # 最多等待 60 秒
                raise Exception("TOFU 验证超时或被用户取消。")
            
            if self.tofu_result: # 如果用户选择信任
                self.identity_manager.add_trusted_peer(
                    self.peer_uuid, self.peer_nickname, self.peer_public_key_pem.decode('utf-8')
                )
                print(f"DEBUG: 已信任 {self.peer_nickname}。")
                self.key_exchange_completed.emit(self.peer_uuid, "公钥交换完成并已信任。")
            else: # 如果用户拒绝信任
                raise Exception("用户拒绝信任，公钥交换失败。")
        else:
            print(f"DEBUG: 邻居 {self.peer_nickname} ({self.peer_uuid[:8]}) 已被信任。")
            self.key_exchange_completed.emit(self.peer_uuid, "公钥交换完成 (已信任)。")

        print(f"DEBUG: 与 {self.peer_nickname} 的公钥交换完成。")

    def send_data_to_peer(self, data_bytes):
        """通过数据套接字发送带长度前缀的数据。"""
        if self.data_socket and self.running and self.is_connected: 
            try:
                msg_len = len(data_bytes)
                len_prefix = struct.pack('>I', msg_len) 
                
                self.data_socket.sendall(len_prefix) 
                self.data_socket.sendall(data_bytes) 
                return True
            except OSError as e: 
                print(f"ERROR: P2PConnectionThread 发送错误 (OSError): {repr(e)}")
                self.running = False 
                self.is_connected = False 
                return False
            except Exception as e:
                print(f"ERROR: P2PConnectionThread 发送错误: {repr(e)}")
                self.running = False 
                self.is_connected = False 
                return False
        else:
            print("ERROR: P2PConnectionThread 发送失败：无有效连接或线程未运行")
            return False

    def stop(self):
        """优雅地停止网络线程。"""
        print(f"DEBUG: 请求停止 P2PConnectionThread ({self.peer_uuid[:8] if self.peer_uuid else self.peer_ip})...")
        self.running = False 
        self.is_connected = False 
        if self.data_socket:
            try: self.data_socket.shutdown(socket.SHUT_RDWR) 
            except OSError: pass
            try: self.data_socket.close()
            except OSError: pass
            self.data_socket = None

# TCPListenerThread (保持不变)
class TCPListenerThread(QThread):
    new_connection_established = pyqtSignal(socket.socket, tuple) 

    def __init__(self, listen_ip, listen_port, parent=None):
        super().__init__(parent)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.running = True
        self.listener_socket = None

    def run(self):
        try:
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind((self.listen_ip, self.listen_port))
            self.listener_socket.listen(5) 
            print(f"DEBUG: TCP 监听线程已在 {self.listen_ip}:{self.listen_port} 上启动监听。")

            self.listener_socket.settimeout(1.0) 

            while self.running:
                try:
                    conn, addr = self.listener_socket.accept()
                    if not self.running: 
                        conn.close()
                        break
                    print(f"DEBUG: 接受到来自 {addr[0]}:{addr[1]} 的新连接。")
                    self.new_connection_established.emit(conn, addr)
                except socket.timeout:
                    continue 
                except OSError as e:
                    if self.running:
                        print(f"ERROR: TCP 监听错误: {e}")
                    break 
                except Exception as e:
                    if self.running:
                        print(f"ERROR: TCP 监听线程未知错误: {e}")
                    break

        except socket.error as e:
            print(f"ERROR: TCP 监听套接字绑定或启动失败: {e}")
        finally:
            self.running = False
            if self.listener_socket:
                self.listener_socket.close()
                self.listener_socket = None
            print("DEBUG: TCP 监听线程已停止。")

    def stop(self):
        print("DEBUG: 请求停止 TCP 监听线程...")
        self.running = False
        if self.listener_socket:
            try: self.listener_socket.close() 
            except OSError: pass

# UDPDiscoveryThread (保持不变)
class UDPDiscoveryThread(QThread):
    peer_discovered = pyqtSignal(dict) 

    def __init__(self, my_uuid, my_nickname, my_tcp_ip, my_tcp_port, my_pk_fingerprint, parent=None):
        super().__init__(parent)
        self.my_uuid = my_uuid
        self.my_nickname = my_nickname
        self.my_tcp_ip = my_tcp_ip 
        self.my_tcp_port = my_tcp_port 
        self.my_pk_fingerprint = my_pk_fingerprint
        
        self.running = True
        self.send_socket = None
        self.recv_socket = None

    def _prepare_broadcast_message(self):
        message = {
            'uuid': self.my_uuid,
            'nickname': self.my_nickname,
            'tcp_ip': self.my_tcp_ip, 
            'tcp_port': self.my_tcp_port,
            'pk_fingerprint': self.my_pk_fingerprint,
            'app_name': "SecureFileTransferP2P", 
            'protocol_version': "1.0"
        }
        return json.dumps(message).encode('utf-8')

    def _send_broadcast(self):
        if not self.send_socket or not self.running:
            return
        
        message_bytes = self._prepare_broadcast_message()
        try:
            self.send_socket.sendto(message_bytes, (BROADCAST_ADDRESS, UDP_DISCOVERY_PORT))
        except socket.error as e:
            print(f"ERROR: 发送UDP广播失败: {e}")

    def run(self):
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 
        
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        try:
            self.recv_socket.bind(('0.0.0.0', UDP_DISCOVERY_PORT)) 
            print(f"DEBUG: UDP发现服务已在 0.0.0.0:{UDP_DISCOVERY_PORT} 上监听...")
        except socket.error as e:
            print(f"ERROR: UDP发现服务绑定到端口 {UDP_DISCOVERY_PORT} 失败: {e}")
            self.running = False 
            return

        self.recv_socket.settimeout(1.0) 

        last_broadcast_time = 0

        while self.running:
            current_time = time.time()
            if current_time - last_broadcast_time >= BROADCAST_INTERVAL_S:
                self._send_broadcast()
                last_broadcast_time = current_time

            try:
                data, addr = self.recv_socket.recvfrom(1024) 
                if data:
                    try:
                        message = json.loads(data.decode('utf-8'))
                        if message.get('uuid') != self.my_uuid: 
                            if all(k in message for k in ['uuid', 'nickname', 'tcp_ip', 'tcp_port', 'pk_fingerprint', 'app_name', 'protocol_version']):
                                peer_info = {
                                    'uuid': message['uuid'],
                                    'nickname': message['nickname'],
                                    'ip': message['tcp_ip'], 
                                    'tcp_port': message['tcp_port'],
                                    'fingerprint': message['pk_fingerprint'],
                                    'source_ip': addr[0], 
                                    'source_port': addr[1], 
                                    'app_name': message['app_name'],
                                    'protocol_version': message['protocol_version']
                                }
                                self.peer_discovered.emit(peer_info)
                            else:
                                print(f"DEBUG: 收到的UDP包缺少必要字段: {message}")
                    except json.JSONDecodeError:
                        print(f"DEBUG: 无法解析来自 {addr} 的UDP JSON数据")
                    except Exception as e_proc:
                        print(f"DEBUG: 处理UDP包时出错 {addr}: {e_proc}")
            except socket.timeout:
                continue 
            except socket.error as e:
                if self.running: 
                    print(f"ERROR: UDP接收错误: {e}")
                time.sleep(0.1) 

        print("DEBUG: UDP发现线程已停止。")
        if self.send_socket:
            try: self.send_socket.close()
            except OSError: pass
        if self.recv_socket:
            try: self.recv_socket.close()
            except OSError: pass

    def stop(self):
        print("DEBUG: 请求停止UDP发现线程...")
        self.running = False
        if self.send_socket:
            try: self.send_socket.close()
            except OSError: pass
        if self.recv_socket:
            try: self.recv_socket.close()
            except OSError: pass
