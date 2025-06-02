import sys
import os
import json 
import zipfile 
import tempfile 
import shutil 
import hashlib 
from datetime import datetime
import time 
import socket 

# PyQt5 模块导入
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QFileDialog,
                             QMessageBox, QTabWidget, QTextEdit, QComboBox,
                             QLineEdit, QGroupBox, QListWidget, 
                             QProgressBar, QInputDialog, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, pyqtSlot 

# 导入自定义模块
from aes_encryption import AES 
from des_encryption import DES 
from rsa_encryption import RSA 
from network_core import P2PConnectionThread, UDPDiscoveryThread, TCPListenerThread, get_suggested_local_ip, UDP_DISCOVERY_PORT, BROADCAST_INTERVAL_S, PEER_TIMEOUT_S, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_FILE_TRANSFER 
from identity_manager import IdentityManager 

class FileEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA() 
        self.is_listening = False 

        self.my_uuid = None
        self.my_nickname = None
        self._my_public_key_pem = None 

        self.identity_manager = IdentityManager(self, self.rsa) 
        
        self.udp_discovery_thread = None
        self.tcp_listener_thread = None 
        self.discovered_peers = {} 
        self.peer_cleanup_timer = QTimer(self) 
        self.active_p2p_sessions = {} # 存储活跃的 P2PConnectionThread 实例

        self.initUI()

    def _post_init_setup(self):
        """
        在主窗口显示后调用，用于加载/创建身份和密钥，并更新UI。
        然后启动P2P发现线程和TCP监听线程。
        """
        print("DEBUG: _post_init_setup: 开始加载/创建身份和密钥...")
        self.identity_manager.load_or_create_identity()
        self.identity_manager.load_or_create_rsa_identity_keys()

        self.my_uuid = self.identity_manager.my_uuid
        self.my_nickname = self.identity_manager.my_nickname
        self._my_public_key_pem = self.identity_manager.get_my_public_key_pem()

        self.my_identity_label.setText(f"<b>本机身份:</b> {self.my_nickname} ({self.my_uuid[:8]}...)")
        self.my_fingerprint_label.setText(f"<b>公钥指纹:</b> {self.get_my_public_key_fingerprint()[:16]}...")
        print("DEBUG: _post_init_setup: 身份和密钥加载完成，UI已更新。")

        self.start_tcp_listener()
        self.start_udp_discovery() 
        
        self.peer_cleanup_timer.timeout.connect(self._check_peer_timeouts)
        self.peer_cleanup_timer.start(int(PEER_TIMEOUT_S * 1000 / 2)) 

    def get_my_public_key_fingerprint(self):
        """
        获取本机身份公钥的 SHA256 指纹（十六进制字符串）。
        此方法现在委托给 IdentityManager。
        """
        if self.identity_manager: 
            return self.identity_manager.get_my_public_key_fingerprint()
        return "初始化中..." 

    def initUI(self):
        self.setWindowTitle('安全文件传输工具 - P2P') 
        self.setGeometry(100, 100, 1100, 800)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        connection_group = QGroupBox("网络连接") 
        connection_layout = QVBoxLayout()
        
        self.my_identity_label = QLabel(f"<b>本机身份:</b> {self.my_nickname if self.my_nickname else '加载中...'} ({self.my_uuid[:8]}...)" if self.my_uuid else "加载中...") 
        self.my_fingerprint_label = QLabel(f"<b>公钥指纹:</b> {self.get_my_public_key_fingerprint()[:16]}...") 
        connection_layout.addWidget(self.my_identity_label)
        connection_layout.addWidget(self.my_fingerprint_label)

        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("本机IP (建议):")) 
        self.ip_input = QLineEdit()
        self.ip_input.setText(get_suggested_local_ip()) 
        self.ip_input.setPlaceholderText("本机监听IP (推荐 0.0.0.0 监听所有网卡)") 
        ip_layout.addWidget(self.ip_input)
        connection_layout.addLayout(ip_layout)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("TCP端口 (监听):")) 
        self.port_input = QLineEdit()
        self.port_input.setText("50000") 
        self.port_input.setPlaceholderText("建议 50000，所有 P2P 节点需一致")
        port_layout.addWidget(self.port_input)
        connection_layout.addLayout(port_layout)
        
        self.conn_tip_label = QLabel(
            '<b style="color:#1976d2">本程序将自动发现局域网内其他节点。您也可以手动指定IP和端口进行连接。</b>'
        )
        self.conn_tip_label.setWordWrap(True)
        connection_layout.addWidget(self.conn_tip_label)
        
        self.connection_status = QLabel("P2P 发现中...") 
        connection_layout.addWidget(self.connection_status)
        
        connection_group.setLayout(connection_layout)
        layout.addWidget(connection_group)

        self.peers_group = QGroupBox("发现的邻居")
        self.peers_layout = QVBoxLayout()
        self.peers_list_widget = QListWidget() 
        self.peers_list_widget.itemDoubleClicked.connect(self._initiate_p2p_connection) 
        self.peers_list_widget.currentItemChanged.connect(self._update_send_button_status)
        self.peers_layout.addWidget(self.peers_list_widget)
        self.peers_group.setLayout(self.peers_layout)
        layout.addWidget(self.peers_group)

        tabs = QTabWidget()
        tabs.setContentsMargins(10, 10, 10, 10)
        tabs.setStyleSheet("QTabBar::tab { min-width: 120px; min-height: 30px; font-size: 15px; }")

        # 一键操作Tab
        quick_action_tab = QWidget()
        quick_action_layout = QVBoxLayout(quick_action_tab)
        quick_action_layout.setSpacing(20)
        quick_action_layout.setContentsMargins(40, 30, 40, 30)

        # 添加说明标签
        quick_action_tip = QLabel(
            '<b style="color:#1976d2;">一键操作页面说明：</b><br>'
            '1. 发送文件：选择文件后，从"发现的邻居"列表中选择接收方，点击"一键发送"<br>'
            '2. 接收文件：程序会自动接收文件，收到文件后会提示保存<br>'
            '3. 所有传输都经过加密和签名，确保安全性'
        )
        quick_action_tip.setWordWrap(True)
        quick_action_tip.setStyleSheet("""
            background-color: #f0f8ff; 
            padding: 15px; 
            border-radius: 8px;
            border: 1px solid #b3e0ff;
            margin-bottom: 10px;
        """)
        quick_action_layout.addWidget(quick_action_tip)
        
        # 发送方操作
        sender_group = QGroupBox("发送方操作")
        sender_layout = QVBoxLayout()
        sender_layout.setSpacing(15)
        
        # 文件选择部分
        file_select_layout = QHBoxLayout()
        self.select_file_btn = QPushButton("选择要发送的文件")
        self.select_file_btn.setIcon(self.style().standardIcon(self.style().SP_FileIcon))
        self.select_file_btn.setFixedWidth(180)
        self.select_file_btn.clicked.connect(self.select_file_to_send)
        self.selected_file_label = QLabel("未选择文件")
        self.selected_file_label.setStyleSheet("color: #666; padding: 5px;")
        self.selected_file_label.setMinimumWidth(350)
        file_select_layout.addWidget(self.select_file_btn)
        file_select_layout.addWidget(self.selected_file_label, 1)
        sender_layout.addLayout(file_select_layout)
        
        # 发送按钮
        self.send_btn = QPushButton("一键发送")
        self.send_btn.setIcon(self.style().standardIcon(self.style().SP_ArrowRight))
        self.send_btn.setFixedWidth(200)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QPushButton:hover:!disabled {
                background-color: #45a049;
            }
        """)
        self.send_btn.clicked.connect(self.quick_send)
        self.send_btn.setEnabled(False)
        sender_layout.addWidget(self.send_btn, alignment=Qt.AlignCenter)
        
        sender_group.setLayout(sender_layout)
        quick_action_layout.addWidget(sender_group)
        
        # 接收方操作
        receiver_group = QGroupBox("接收方操作")
        receiver_layout = QVBoxLayout()
        receiver_layout.setSpacing(15)
        
        # 接收状态显示
        self.receive_status_label = QLabel("等待接收文件...")
        self.receive_status_label.setStyleSheet("""
            color: #666; 
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 5px;
            border: 1px solid #ddd;
        """)
        receiver_layout.addWidget(self.receive_status_label)
        
        # 接收按钮
        self.receive_btn = QPushButton("一键接收 (等待数据)")
        self.receive_btn.setIcon(self.style().standardIcon(self.style().SP_ArrowDown))
        self.receive_btn.setFixedWidth(200)
        self.receive_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.receive_btn.clicked.connect(self.quick_receive_setup)
        receiver_layout.addWidget(self.receive_btn, alignment=Qt.AlignCenter)
        
        receiver_group.setLayout(receiver_layout)
        quick_action_layout.addWidget(receiver_group)
        
        # 进度条
        progress_group = QGroupBox("传输进度")
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
                height: 25px;
                font-size: 13px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        progress_group.setLayout(progress_layout)
        quick_action_layout.addWidget(progress_group)
        
        # 添加状态提示
        self.status_tip_label = QLabel("")
        self.status_tip_label.setStyleSheet("""
            color: #666; 
            font-style: italic;
            padding: 10px;
            background-color: #fffde7;
            border-radius: 5px;
            border: 1px solid #ffe082;
        """)
        self.status_tip_label.setWordWrap(True)
        quick_action_layout.addWidget(self.status_tip_label)
        
        quick_action_layout.addStretch()
        quick_action_tab.setLayout(quick_action_layout)

        # 文件加密Tab
        enc_tab = QWidget()
        enc_layout = QVBoxLayout(enc_tab)
        enc_layout.setSpacing(20)
        enc_layout.setContentsMargins(40, 30, 40, 30)
        enc_file_group = QGroupBox("文件选择")
        enc_file_group_layout = QHBoxLayout()
        self.enc_file_label = QLabel('未选择文件')
        self.enc_file_label.setMinimumWidth(350)
        enc_file_btn = QPushButton('选择文件')
        enc_file_btn.setFixedWidth(120)
        enc_file_btn.clicked.connect(self.select_enc_file)
        enc_file_group_layout.addWidget(self.enc_file_label)
        enc_file_group_layout.addWidget(enc_file_btn)
        enc_file_group.setLayout(enc_file_group_layout)
        enc_layout.addWidget(enc_file_group)
        # 算法选择
        enc_algo_group = QGroupBox("加密算法")
        enc_algo_layout = QHBoxLayout()
        self.enc_algo_combo = QComboBox()
        self.enc_algo_combo.addItems(['AES', 'DES'])
        enc_algo_layout.addWidget(QLabel('算法:'))
        enc_algo_layout.addWidget(self.enc_algo_combo)
        enc_algo_group.setLayout(enc_algo_layout)
        enc_layout.addWidget(enc_algo_group)
        # 加密按钮
        enc_btn = QPushButton('加密')
        enc_btn.setFixedWidth(150)
        enc_btn.clicked.connect(self.encrypt_file)
        enc_layout.addWidget(enc_btn, alignment=Qt.AlignCenter)
        # 结果
        enc_result_group = QGroupBox("加密结果")
        enc_result_layout = QVBoxLayout()
        self.enc_key_path_label = QLabel('明文密钥txt路径: ')
        self.enc_out_path_label = QLabel('加密文件路径: ')
        enc_result_layout.addWidget(self.enc_key_path_label)
        enc_result_layout.addWidget(self.enc_out_path_label)
        enc_result_group.setLayout(enc_result_layout)
        enc_layout.addWidget(enc_result_group)
        enc_layout.addStretch(1)

        # 密钥加密Tab
        key_enc_tab = QWidget()
        key_enc_layout = QVBoxLayout(key_enc_tab)
        key_enc_layout.setSpacing(20)
        key_enc_layout.setContentsMargins(40, 30, 40, 30)
        key_enc_file_group = QGroupBox("明文密钥选择")
        key_enc_file_layout = QHBoxLayout()
        self.key_enc_file_label = QLabel('未选择明文密钥txt')
        self.key_enc_file_label.setMinimumWidth(350)
        key_enc_file_btn = QPushButton('选择明文密钥txt')
        key_enc_file_btn.setFixedWidth(150)
        key_enc_file_btn.clicked.connect(self.select_key_enc_file)
        key_enc_file_layout.addWidget(self.key_enc_file_label)
        key_enc_file_layout.addWidget(key_enc_file_btn)
        key_enc_file_group.setLayout(key_enc_file_layout)
        key_enc_layout.addWidget(key_enc_file_group)
        key_enc_btn = QPushButton('RSA加密密钥')
        key_enc_btn.setFixedWidth(180)
        key_enc_btn.clicked.connect(self.key_encrypt)
        key_enc_layout.addWidget(key_enc_btn, alignment=Qt.AlignCenter)
        key_enc_result_group = QGroupBox("加密结果")
        key_enc_result_layout = QVBoxLayout()
        self.key_enc_out_path_label = QLabel('RSA加密密钥文件路径: ')
        key_enc_result_layout.addWidget(self.key_enc_out_path_label)
        key_enc_result_group.setLayout(key_enc_result_layout)
        key_enc_layout.addWidget(key_enc_result_group)
        key_enc_layout.addStretch(1)

        # SHA+RSA签名Tab
        sign_tab = QWidget()
        sign_layout = QVBoxLayout(sign_tab)
        sign_layout.setSpacing(20)
        sign_layout.setContentsMargins(40, 30, 40, 30)
        sign_file_group = QGroupBox("加密文件选择")
        sign_file_layout = QHBoxLayout()
        self.sign_file_label = QLabel('未选择文件')
        self.sign_file_label.setMinimumWidth(350)
        sign_file_btn = QPushButton('选择加密文件')
        sign_file_btn.setFixedWidth(150)
        sign_file_btn.clicked.connect(self.select_sign_file)
        sign_file_layout.addWidget(self.sign_file_label)
        sign_file_layout.addWidget(sign_file_btn)
        sign_file_group.setLayout(sign_file_layout)
        sign_layout.addWidget(sign_file_group)
        sign_btn = QPushButton('签名')
        sign_btn.setFixedWidth(150)
        sign_btn.clicked.connect(self.sign_file)
        sign_layout.addWidget(sign_btn, alignment=Qt.AlignCenter)
        sign_result_group = QGroupBox("签名结果")
        sign_result_layout = QVBoxLayout()
        self.sign_path_label = QLabel('签名文件路径: ')
        sign_result_layout.addWidget(self.sign_path_label)
        sign_result_group.setLayout(sign_result_layout)
        sign_layout.addWidget(sign_result_group)
        sign_layout.addStretch(1)

        # 认证Tab
        auth_tab = QWidget()
        auth_layout = QVBoxLayout(auth_tab)
        auth_layout.setSpacing(20)
        auth_layout.setContentsMargins(40, 30, 40, 30)
        auth_file_group = QGroupBox("加密文件和签名文件选择")
        auth_file_layout = QHBoxLayout()
        self.auth_file_label = QLabel('未选择原始文件')
        self.auth_file_label.setMinimumWidth(250)
        auth_file_btn = QPushButton('选择加密文件')
        auth_file_btn.setFixedWidth(120)
        auth_file_btn.clicked.connect(self.select_auth_file)
        self.auth_sig_label = QLabel('未选择签名文件')
        self.auth_sig_label.setMinimumWidth(250)
        auth_sig_btn = QPushButton('选择签名文件')
        auth_sig_btn.setFixedWidth(120)
        auth_sig_btn.clicked.connect(self.select_auth_sig)
        auth_file_layout.addWidget(self.auth_file_label)
        auth_file_layout.addWidget(auth_file_btn)
        auth_file_layout.addWidget(self.auth_sig_label)
        auth_file_layout.addWidget(auth_sig_btn)
        auth_file_group.setLayout(auth_file_layout)
        auth_layout.addWidget(auth_file_group)
        auth_btn = QPushButton('认证')
        auth_btn.setFixedWidth(150)
        auth_btn.clicked.connect(self.auth_verify)
        auth_layout.addWidget(auth_btn, alignment=Qt.AlignCenter)
        auth_result_group = QGroupBox("认证结果")
        auth_result_layout = QVBoxLayout()
        self.auth_result_label = QLabel('认证结果: ')
        auth_result_layout.addWidget(self.auth_result_label)
        auth_result_group.setLayout(auth_result_layout)
        auth_layout.addWidget(auth_result_group)
        auth_layout.addStretch(1)

        # 密钥解密Tab
        key_dec_tab = QWidget()
        key_dec_layout = QVBoxLayout(key_dec_tab)
        key_dec_layout.setSpacing(20)
        key_dec_layout.setContentsMargins(40, 30, 40, 30)
        key_dec_file_group = QGroupBox("RSA加密密钥文件选择")
        key_dec_file_layout = QHBoxLayout()
        self.key_dec_file_label = QLabel('未选择RSA加密密钥文件')
        self.key_dec_file_label.setMinimumWidth(350)
        key_dec_file_btn = QPushButton('选择RSA加密密钥文件')
        key_dec_file_btn.setFixedWidth(180)
        key_dec_file_btn.clicked.connect(self.select_key_dec_file)
        key_dec_file_layout.addWidget(self.key_dec_file_label)
        key_dec_file_layout.addWidget(key_dec_file_btn)
        key_dec_file_group.setLayout(key_dec_file_layout)
        key_dec_layout.addWidget(key_dec_file_group)
        key_dec_btn = QPushButton('解密密钥')
        key_dec_btn.setFixedWidth(150)
        key_dec_btn.clicked.connect(self.key_decrypt)
        key_dec_layout.addWidget(key_dec_btn, alignment=Qt.AlignCenter)
        key_dec_result_group = QGroupBox("解密结果")
        key_dec_result_layout = QVBoxLayout()
        self.key_dec_out_path_label = QLabel('明文密钥txt路径: ')
        key_dec_result_layout.addWidget(self.key_dec_out_path_label)
        key_dec_result_group.setLayout(key_dec_result_layout)
        key_dec_layout.addWidget(key_dec_result_group)
        key_dec_layout.addStretch(1)

        # 文件解密Tab
        file_dec_tab = QWidget()
        file_dec_layout = QVBoxLayout(file_dec_tab)
        file_dec_layout.setSpacing(20)
        file_dec_layout.setContentsMargins(40, 30, 40, 30)
        file_dec_file_group = QGroupBox("加密文件和明文密钥选择")
        file_dec_file_layout = QHBoxLayout()
        self.file_dec_file_label = QLabel('未选择加密文件')
        self.file_dec_file_label.setMinimumWidth(250)
        file_dec_file_btn = QPushButton('选择加密文件')
        file_dec_file_btn.setFixedWidth(120)
        file_dec_file_btn.clicked.connect(self.select_file_dec_file)
        self.file_dec_key_label = QLabel('未选择明文密钥txt')
        self.file_dec_key_label.setMinimumWidth(250)
        file_dec_key_btn = QPushButton('选择明文密钥txt')
        file_dec_key_btn.setFixedWidth(120)
        file_dec_key_btn.clicked.connect(self.select_file_dec_key)
        file_dec_file_layout.addWidget(self.file_dec_file_label)
        file_dec_file_layout.addWidget(file_dec_file_btn)
        file_dec_file_layout.addWidget(self.file_dec_key_label)
        file_dec_file_layout.addWidget(file_dec_key_btn)
        file_dec_file_group.setLayout(file_dec_file_layout)
        file_dec_layout.addWidget(file_dec_file_group)
        file_dec_algo_group = QGroupBox("解密算法")
        file_dec_algo_layout = QHBoxLayout()
        self.file_dec_algo_combo = QComboBox()
        self.file_dec_algo_combo.addItems(['AES', 'DES'])
        file_dec_algo_layout.addWidget(QLabel('算法:'))
        file_dec_algo_layout.addWidget(self.file_dec_algo_combo)
        file_dec_algo_group.setLayout(file_dec_algo_layout)
        file_dec_layout.addWidget(file_dec_algo_group)
        file_dec_btn = QPushButton('解密文件')
        file_dec_btn.setFixedWidth(150)
        file_dec_btn.clicked.connect(self.file_decrypt)
        file_dec_layout.addWidget(file_dec_btn, alignment=Qt.AlignCenter)
        file_dec_result_group = QGroupBox("解密结果")
        file_dec_result_layout = QVBoxLayout()
        self.file_dec_out_path_label = QLabel('解密文件路径: ')
        file_dec_result_layout.addWidget(self.file_dec_out_path_label)
        file_dec_result_group.setLayout(file_dec_result_layout)
        file_dec_layout.addWidget(file_dec_result_group)
        file_dec_layout.addStretch(1)

        # 密钥管理Tab
        key_manage_tab = QWidget()
        key_manage_layout = QVBoxLayout(key_manage_tab)
        key_manage_layout.setSpacing(20)
        key_manage_layout.setContentsMargins(40, 30, 40, 30)
        # 生成新密钥对
        generate_key_group = QGroupBox("生成新密钥对")
        generate_key_layout = QHBoxLayout()
        generate_key_btn = QPushButton("生成新的RSA密钥对")
        generate_key_btn.setFixedWidth(200)
        generate_key_btn.clicked.connect(self.generate_new_keypair)
        generate_key_layout.addWidget(generate_key_btn)
        generate_key_group.setLayout(generate_key_layout)
        key_manage_layout.addWidget(generate_key_group) 
        # 导出公钥
        export_pub_group = QGroupBox("导出公钥")
        export_pub_layout = QHBoxLayout()
        export_pub_btn = QPushButton("导出公钥")
        export_pub_btn.setFixedWidth(150)
        export_pub_btn.clicked.connect(self.export_public_key)
        export_pub_layout.addWidget(export_pub_btn)
        export_pub_group.setLayout(export_pub_layout)
        key_manage_layout.addWidget(export_pub_group) 
        # 新增：导入信任公钥
        import_trusted_pub_group = QGroupBox("导入信任公钥")
        import_trusted_pub_layout = QHBoxLayout()
        import_trusted_pub_btn = QPushButton("导入信任公钥")
        import_trusted_pub_btn.setFixedWidth(150)
        import_trusted_pub_btn.clicked.connect(self.import_trusted_peer_public_key)
        import_trusted_pub_layout.addWidget(import_trusted_pub_btn)
        import_trusted_pub_group.setLayout(import_trusted_pub_layout)
        key_manage_layout.addWidget(import_trusted_pub_group)
        # 导出私钥
        export_priv_group = QGroupBox("导出私钥")
        export_priv_layout = QHBoxLayout()
        export_priv_btn = QPushButton("导出私钥")
        export_priv_btn.setFixedWidth(150)
        export_priv_btn.clicked.connect(self.export_private_key)
        export_priv_layout.addWidget(export_priv_btn)
        export_priv_group.setLayout(export_priv_layout)
        key_manage_layout.addWidget(export_priv_group) 
        # 导入公钥
        import_pub_group = QGroupBox("导入公钥")
        import_pub_layout = QHBoxLayout()
        import_pub_btn = QPushButton("导入公钥")
        import_pub_btn.setFixedWidth(150)
        import_pub_btn.clicked.connect(self.import_public_key)
        import_pub_layout.addWidget(import_pub_btn)
        import_pub_group.setLayout(import_pub_layout)
        key_manage_layout.addWidget(import_pub_group) 
        # 导入私钥
        import_priv_group = QGroupBox("导入私钥")
        import_priv_layout = QHBoxLayout()
        import_priv_btn = QPushButton("导入私钥")
        import_priv_btn.setFixedWidth(150)
        import_priv_btn.clicked.connect(self.import_private_key)
        import_priv_layout.addWidget(import_priv_btn)
        import_priv_group.setLayout(import_priv_layout)
        key_manage_layout.addWidget(import_priv_group) 
        key_manage_layout.addStretch(1)
        key_manage_tab.setLayout(key_manage_layout) 

        # 更新功能介绍页面
        tutorial_tab = QWidget()
        tutorial_layout = QVBoxLayout(tutorial_tab)
        tutorial_layout.setSpacing(20)
        tutorial_layout.setContentsMargins(40, 30, 40, 30)
        
        tutorial_text = QTextEdit()
        tutorial_text.setReadOnly(True)
        tutorial_text.setHtml('''
        <h2 style="color: #1976d2;">安全文件传输工具使用手册</h2>
        
        <h3 style="color: #2196F3;">1. P2P网络发现与连接</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>基本概念</h4>
            <ul>
                <li>程序启动后自动发现局域网内的其他节点，在"发现的邻居"列表中显示</li>
                <li>每个节点既是发送方也是接收方，无需手动选择角色</li>
                <li>首次连接时会进行身份验证，确保通信安全</li>
            </ul>
            
            <h4>网络配置</h4>
            <ul>
                <li><b>本机IP (建议)</b>：程序自动检测本地IP。如无法连接，请：
                    <ul>
                        <li>手动输入真实局域网IP（通过 <code>ipconfig</code> 获取）</li>
                        <li>或使用 <code>0.0.0.0</code> 监听所有网卡</li>
                    </ul>
                </li>
                <li><b>TCP端口 (监听)</b>：所有节点使用相同端口，默认50000</li>
                <li><b>公钥指纹</b>：首次连接时用于验证对方身份，请通过安全渠道核对</li>
            </ul>
        </div>

        <h3 style="color: #2196F3;">2. 一键操作（推荐使用）</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>发送文件</h4>
            <ol>
                <li>点击"选择要发送的文件"按钮选择文件</li>
                <li>在"发现的邻居"列表中选择接收方</li>
                <li>点击"一键发送"按钮</li>
                <li>等待传输完成提示</li>
            </ol>
            
            <h4>接收文件</h4>
            <ol>
                <li>程序自动接收文件，无需手动操作</li>
                <li>收到文件时会弹出保存对话框</li>
                <li>选择保存位置后自动解密并保存</li>
            </ol>
            
            <p style="color: #d32f2f;"><b>注意：</b>首次与对方通信时，需要验证对方身份。请通过其他安全渠道（如电话、短信）核对公钥指纹。</p>
        </div>

        <h3 style="color: #2196F3;">3. 手动操作功能</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>文件加密</h4>
            <ul>
                <li>支持AES和DES两种加密算法</li>
                <li>生成加密文件和对应的密钥文件</li>
            </ul>
            
            <h4>密钥加密</h4>
            <ul>
                <li>使用RSA算法加密对称密钥</li>
                <li>确保密钥传输安全</li>
            </ul>
            
            <h4>文件签名与验证</h4>
            <ul>
                <li>使用SHA256+RSA进行签名</li>
                <li>验证文件完整性和发送方身份</li>
            </ul>
            
            <h4>文件解密</h4>
            <ul>
                <li>先解密RSA加密的密钥</li>
                <li>使用解密后的密钥解密文件</li>
            </ul>
        </div>

        <h3 style="color: #2196F3;">4. 密钥管理</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <ul>
                <li>生成新的RSA密钥对</li>
                <li>导出公钥和私钥</li>
                <li>导入他人的公钥</li>
                <li>导入自己的私钥</li>
            </ul>
            <p style="color: #d32f2f;"><b>安全提示：</b>请妥善保管私钥，不要泄露给他人。</p>
        </div>

        <h3 style="color: #2196F3;">5. 常见问题</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h4>连接问题</h4>
            <ul>
                <li><b>端口被占用：</b>更换端口或重启程序</li>
                <li><b>无法发现邻居：</b>检查防火墙设置，确保UDP广播未被阻止</li>
                <li><b>连接超时：</b>确认对方在线且网络正常</li>
            </ul>
            
            <h4>传输问题</h4>
            <ul>
                <li><b>文件发送失败：</b>检查网络连接和接收方状态</li>
                <li><b>解密失败：</b>确认使用了正确的密钥和算法</li>
                <li><b>验证失败：</b>检查签名文件是否完整</li>
            </ul>
        </div>
        ''')
        tutorial_layout.addWidget(tutorial_text)
        tutorial_tab.setLayout(tutorial_layout)

        # 添加标签页到 TabWidget
        tabs.addTab(quick_action_tab, "一键操作") 
        tabs.addTab(enc_tab, "文件加密")
        tabs.addTab(key_enc_tab, "密钥加密")
        tabs.addTab(sign_tab, "SHA+RSA签名")
        tabs.addTab(auth_tab, "认证")
        tabs.addTab(key_dec_tab, "密钥解密")
        tabs.addTab(file_dec_tab, "文件解密")
        tabs.addTab(key_manage_tab, "密钥管理")
        tabs.addTab(tutorial_tab, "页面功能介绍")
        layout.addWidget(tabs)
        main_widget.setLayout(layout)

    # --- NEW --- 启动 TCP 监听线程的方法
    def start_tcp_listener(self):
        try:
            listen_ip = self.ip_input.text() # 使用 UI 上显示的 IP 作为监听 IP
            listen_port = int(self.port_input.text())

            self.tcp_listener_thread = TCPListenerThread(listen_ip, listen_port)
            self.tcp_listener_thread.new_connection_established.connect(self._handle_incoming_connection)
            self.tcp_listener_thread.start()
            self.connection_status.setText(f"TCP 监听中于 {listen_ip}:{listen_port}...")
            print(f"DEBUG: TCP 监听线程已启动于 {listen_ip}:{listen_port}")
        except Exception as e:
            QMessageBox.critical(self, "TCP 监听错误", f"无法启动 TCP 监听：{e}")
            self.connection_status.setText("TCP 监听启动失败")

    # --- NEW --- 处理入站 TCP 连接
    @pyqtSlot(socket.socket, tuple)
    def _handle_incoming_connection(self, conn_socket, addr_info):
        peer_ip, peer_port = addr_info
        print(f"DEBUG: 收到来自 {peer_ip}:{peer_port} 的入站连接。")
        
        p2p_session_thread = P2PConnectionThread(
            my_uuid=self.my_uuid,
            my_nickname=self.my_nickname,
            my_pk_fingerprint=self.get_my_public_key_fingerprint(),
            rsa_instance=self.rsa, # 传递 RSA 实例
            identity_manager=self.identity_manager, # 传递 IdentityManager
            socket_obj=conn_socket, # 传入已接受的 socket
            peer_ip=peer_ip, # 传入对方 IP
            peer_port=peer_port # 传入对方端口
        )
        p2p_session_thread.message_received.connect(self.handle_message)
        p2p_session_thread.key_exchange_completed.connect(self._handle_key_exchange_completed)
        p2p_session_thread.peer_disconnected.connect(self._handle_peer_disconnected)
        p2p_session_thread.request_tofu_verification.connect(self._handle_tofu_request)
        p2p_session_thread.start()
        # 暂时用 socket.fileno() 作为键，待公钥交换完成后更新为真实的 peer_uuid
        self.active_p2p_sessions[conn_socket.fileno()] = p2p_session_thread 

    # --- NEW --- 从 UI 列表双击发起 P2P 连接
    @pyqtSlot(QListWidgetItem)
    def _initiate_p2p_connection(self, item): 
        peer_uuid = item.data(Qt.UserRole)
        peer_data = self.discovered_peers.get(peer_uuid)

        if not peer_data:
            QMessageBox.warning(self.parent(), "错误", "邻居信息无效或已离线。") 
            self._update_peers_ui_list() 
            return

        # 检查是否已经存在与该邻居的活跃连接
        for session_key, session_thread in list(self.active_p2p_sessions.items()): 
            if (session_thread.peer_uuid == peer_uuid and session_thread.is_connected) or \
               (session_thread.peer_uuid is None and session_thread.peer_ip == peer_data['ip'] and session_thread.peer_port == peer_data['tcp_port'] and session_thread.is_connected):
                QMessageBox.information(self.parent(), "提示", f"已与 {peer_data['nickname']} 建立连接。")
                return

        print(f"DEBUG: 尝试连接到 {peer_data['nickname']} ({peer_data['ip']}:{peer_data['tcp_port']})")
        
        p2p_session_thread = P2PConnectionThread(
            my_uuid=self.my_uuid,
            my_nickname=self.my_nickname,
            my_pk_fingerprint=self.get_my_public_key_fingerprint(),
            rsa_instance=self.rsa, 
            identity_manager=self.identity_manager, 
            peer_ip=peer_data['ip'], 
            peer_port=peer_data['tcp_port'] 
        )
        p2p_session_thread.message_received.connect(self.handle_message)
        p2p_session_thread.key_exchange_completed.connect(self._handle_key_exchange_completed)
        p2p_session_thread.peer_disconnected.connect(self._handle_peer_disconnected)
        p2p_session_thread.request_tofu_verification.connect(self._handle_tofu_request)
        p2p_session_thread.start()
        self.active_p2p_sessions[peer_uuid] = p2p_session_thread 
        self._update_send_button_status()

    # --- NEW --- 处理公钥交换完成信号
    @pyqtSlot(str, str) 
    def _handle_key_exchange_completed(self, peer_uuid, status_message):
        session_thread_to_update = None
        temp_key_to_remove = None
        for key, thread_instance in list(self.active_p2p_sessions.items()): 
            if thread_instance.peer_uuid == peer_uuid: 
                session_thread_to_update = thread_instance
                if key != peer_uuid: 
                    temp_key_to_remove = key
                break
        
        if session_thread_to_update:
            if temp_key_to_remove is not None and temp_key_to_remove in self.active_p2p_sessions: 
                del self.active_p2p_sessions[temp_key_to_remove]
                self.active_p2p_sessions[peer_uuid] = session_thread_to_update 
            
            print(f"DEBUG: 与 {session_thread_to_update.peer_nickname} ({peer_uuid[:8]}) 的公钥交换完成: {status_message}")
            self._update_peers_ui_list() 
            self._update_send_button_status() 
        else:
            print(f"DEBUG: 公钥交换完成，但找不到会话线程: {peer_uuid}")

    # --- NEW --- 处理对端断开连接信号
    @pyqtSlot(str) 
    def _handle_peer_disconnected(self, peer_identifier):
        print(f"DEBUG: 邻居 {peer_identifier[:8]} 已断开连接。")
        
        key_to_remove = None
        if peer_identifier in self.active_p2p_sessions:
            key_to_remove = peer_identifier
        else: 
            for key, thread_instance in list(self.active_p2p_sessions.items()):
                 if hasattr(thread_instance, 'peer_ip') and f"unidentified_peer_{thread_instance.peer_ip}:{thread_instance.peer_port}" == peer_identifier:
                    key_to_remove = key
                    break
        
        if key_to_remove and key_to_remove in self.active_p2p_sessions:
            session_thread = self.active_p2p_sessions[key_to_remove]
            if session_thread and session_thread.isRunning(): 
                session_thread.stop() 
                session_thread.wait(1000) 
            del self.active_p2p_sessions[key_to_remove]
        
        self._update_peers_ui_list() 
        self._update_send_button_status() 

    # --- NEW --- 处理 TOFU 验证请求 (主线程中弹出对话框)
    @pyqtSlot(dict, QThread) 
    def _handle_tofu_request(self, tofu_info, session_thread):
        print(f"DEBUG: 主线程收到 TOFU 验证请求，来自 {tofu_info['nickname']} ({tofu_info['peer_uuid'][:8]})")
        
        reply = QMessageBox.question(self, "首次使用信任 (TOFU) 验证",
                                     f"您正在与一个新伙伴建立连接：\n\n"
                                     f"昵称: {tofu_info['nickname']}\n"
                                     f"UUID: {tofu_info['peer_uuid']}\n"
                                     f"公钥指纹 (SHA256): {tofu_info['fingerprint']}\n\n"
                                     f"请通过其他安全渠道（如电话、短信等）核对上述指纹，以确保没有中间人攻击。\n\n"
                                     f"是否信任此伙伴并继续？",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            session_thread.tofu_result = True
            self.identity_manager.add_trusted_peer(
                tofu_info['peer_uuid'], tofu_info['nickname'], tofu_info['public_key_pem']
            )
            QMessageBox.information(self, "信任成功", f"已信任 {tofu_info['nickname']}。")
        else:
            session_thread.tofu_result = False
            QMessageBox.warning(self, "信任拒绝", f"您已拒绝信任 {tofu_info['nickname']}。连接将被断开。")
        
        session_thread.tofu_event.set() 
        self._update_peers_ui_list() 

    def start_udp_discovery(self):
        if not self.my_uuid or not hasattr(self, 'rsa') or self.rsa.get_public_key() is None:
            QMessageBox.warning(self, "错误", "无法启动P2P发现：身份或密钥未正确初始化。")
            self.connection_status.setText("P2P发现启动失败")
            return

        advertised_tcp_ip = self.ip_input.text()
        if advertised_tcp_ip == '0.0.0.0':
            specific_lan_ip = get_suggested_local_ip()
            if specific_lan_ip == '127.0.0.1' or specific_lan_ip == '0.0.0.0':
                 QMessageBox.warning(self, "网络配置警告", 
                                     f"您选择监听 0.0.0.0，但未能自动检测到合适的局域网IP进行广播。\n"
                                     f"其他节点可能无法通过广播发现您。请考虑在IP栏输入一个具体的局域网IP。")
                 advertised_tcp_ip = specific_lan_ip 
            else:
                 advertised_tcp_ip = specific_lan_ip
            print(f"DEBUG: 监听0.0.0.0，将广播TCP IP为: {advertised_tcp_ip}")


        try:
            my_tcp_listen_port = int(self.port_input.text())
        except ValueError:
            QMessageBox.critical(self, "端口错误", "TCP监听端口号无效。")
            self.connection_status.setText("P2P发现启动失败")
            return

        self.udp_discovery_thread = UDPDiscoveryThread(
            my_uuid=self.my_uuid,
            my_nickname=self.my_nickname,
            my_tcp_ip=advertised_tcp_ip, 
            my_tcp_port=my_tcp_listen_port, 
            my_pk_fingerprint=self.get_my_public_key_fingerprint()
        )
        self.udp_discovery_thread.peer_discovered.connect(self.handle_peer_discovered)
        self.udp_discovery_thread.finished.connect(self.on_discovery_thread_finished) 
        self.udp_discovery_thread.start()
        self.connection_status.setText("P2P 发现中...")

    def on_discovery_thread_finished(self): 
        print("DEBUG: UDP发现线程已终止。")
        self.connection_status.setText("P2P 发现已停止")

    @pyqtSlot(dict) 
    def handle_peer_discovered(self, peer_info):
        peer_uuid = peer_info.get('uuid')
        if not peer_uuid:
            return

        if peer_uuid == self.my_uuid:
            return

        self.discovered_peers[peer_uuid] = {
            'nickname': peer_info.get('nickname'),
            'ip': peer_info.get('ip'), 
            'tcp_port': peer_info.get('tcp_port'),
            'fingerprint': peer_info.get('fingerprint'),
            'source_ip': peer_info.get('source_ip'), 
            'source_port': peer_info.get('source_port'), 
            'app_name': peer_info.get('app_name'),
            'protocol_version': peer_info.get('protocol_version'),
            'last_seen': time.time(), 
            'status': '在线' 
        }
        self._update_peer_status_in_dict(peer_uuid) 
        self._update_peers_ui_list()

    def _update_peer_status_in_dict(self, peer_uuid):
        if peer_uuid in self.discovered_peers:
            base_status = '在线'
            if peer_uuid in self.active_p2p_sessions:
                session = self.active_p2p_sessions[peer_uuid]
                if session.is_connected: 
                    base_status = '已连接'
            
            if self.identity_manager.is_peer_trusted(peer_uuid):
                self.discovered_peers[peer_uuid]['status'] = f"{base_status} (已信任)"
            else:
                self.discovered_peers[peer_uuid]['status'] = base_status


    def _update_peers_ui_list(self):
        # 保存当前选中项的UUID
        current_selected_uuid = None
        selected_items = self.peers_list_widget.selectedItems()
        if selected_items:
            current_selected_uuid = selected_items[0].data(Qt.UserRole)

        self.peers_list_widget.clear()
        current_time = time.time()
        
        # 首先更新所有已知邻居的状态
        for uuid_key in list(self.discovered_peers.keys()):
            if uuid_key in self.discovered_peers: 
                self._update_peer_status_in_dict(uuid_key)

        # 按昵称排序邻居
        sorted_peers = sorted(self.discovered_peers.items(), key=lambda item: item[1].get('nickname', ''))

        selected_item_to_restore = None
        for uuid_key, peer_data in sorted_peers:
            if current_time - peer_data.get('last_seen', 0) < PEER_TIMEOUT_S: 
                display_text = f"{peer_data['nickname']} ({peer_data['ip']}:{peer_data['tcp_port']}) - {peer_data['status']}"
                item = QListWidgetItem(display_text)
                item.setData(Qt.UserRole, uuid_key) 
                self.peers_list_widget.addItem(item)
                
                # 如果是之前选中的项，记录下来
                if uuid_key == current_selected_uuid:
                    selected_item_to_restore = item
        
        # 恢复选中状态
        if selected_item_to_restore:
            # 临时屏蔽信号以避免触发不必要的信号处理
            self.peers_list_widget.blockSignals(True)
            self.peers_list_widget.setCurrentItem(selected_item_to_restore)
            self.peers_list_widget.blockSignals(False)
            
        # 无论是否恢复了选择，都更新按钮状态
        self._update_send_button_status()

    def _check_peer_timeouts(self):
        current_time = time.time()
        peers_changed = False
        for uuid_key, peer_data in list(self.discovered_peers.items()):
            if current_time - peer_data.get('last_seen', 0) >= PEER_TIMEOUT_S:
                print(f"DEBUG: 邻居 {peer_data['nickname']} ({uuid_key[:8]}) 超时，将移除。")
                # 如果有活跃会话，也需要处理
                if uuid_key in self.active_p2p_sessions:
                    session_thread = self.active_p2p_sessions[uuid_key]
                    if session_thread and session_thread.isRunning():
                        session_thread.stop() 
                        session_thread.wait(1000)
                    del self.active_p2p_sessions[uuid_key] 
                del self.discovered_peers[uuid_key]
                peers_changed = True
        
        if peers_changed:
            self._update_peers_ui_list()
            self._update_send_button_status() 
            
        def start_listen(self):
            QMessageBox.information(self, "提示", "P2P 模式下，程序将自动监听，无需手动启动。")

    def toggle_connection_client(self):
        QMessageBox.information(self, "提示", "P2P 模式下，请从'发现的邻居'列表中选择节点进行连接。")

    def update_connection_status(self, connected, message):
        self.connection_status.setText(message)
        self._update_send_button_status() 

    def on_network_thread_finished(self): 
        self.connection_status.setText("P2P 发现中...") 
        self._update_send_button_status()

    def _create_new_temp_dir(self):
        return tempfile.mkdtemp()

    def pack_files(self, file_path, key_path, sig_path):
        packaging_temp_dir = self._create_new_temp_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"secure_package_{timestamp}.zip"
        zip_path = os.path.join(packaging_temp_dir, zip_filename)
        
        original_base_filename = os.path.basename(file_path)
        encryption_type = 'UNKNOWN'
        if '.AES.enc' in original_base_filename:
            encryption_type = 'AES'
            original_base_filename = original_base_filename.replace('.AES.enc', '')
        elif '.DES.enc' in original_base_filename:
            encryption_type = 'DES'
            original_base_filename = original_base_filename.replace('.DES.enc', '')
        
        metadata_content = {
            'timestamp': timestamp,
            'original_filename': original_base_filename,
            'encryption_type': encryption_type
        }
        metadata_file_path = os.path.join(packaging_temp_dir, 'metadata.json')

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(file_path, os.path.basename(file_path))
            zipf.write(key_path, os.path.basename(key_path))
            zipf.write(sig_path, os.path.basename(sig_path))
            with open(metadata_file_path, 'w', encoding='utf-8') as f: 
                json.dump(metadata_content, f, indent=4, ensure_ascii=False) 
            zipf.write(metadata_file_path, 'metadata.json')
        
        os.remove(metadata_file_path) 
        return zip_path, packaging_temp_dir

    def unpack_files(self, zip_path):
        extract_target_dir = self._create_new_temp_dir()
        metadata = {}
        try:
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                if 'metadata.json' not in zipf.namelist():
                    raise ValueError("压缩包中缺少 metadata.json 文件。")
                
                with zipf.open('metadata.json', 'r') as meta_f:
                    metadata = json.load(meta_f)
                
                zipf.extractall(extract_target_dir)
        except Exception as e:
            if os.path.exists(extract_target_dir):
                shutil.rmtree(extract_target_dir)
            raise Exception(f"解包文件失败: {e}")
        
        return extract_target_dir, metadata

    @pyqtSlot(str, str) 
    def handle_message(self, message_str, peer_uuid):
        if peer_uuid not in self.active_p2p_sessions:
            print(f"DEBUG: 收到来自未知会话 {peer_uuid[:8]} 的消息，忽略。")
            return

        try:
            data = json.loads(message_str) 
            if data.get('type') == MSG_TYPE_KEY_EXCHANGE: 
                print(f"DEBUG: UI 收到来自 {peer_uuid[:8]} 的密钥交换确认消息。")
                return 

            elif data.get('type') == 'package': # 旧的文件传输格式
                self.progress_bar.setVisible(True) 
                self.progress_bar.setRange(0,0) 

                package_receive_temp_dir = None
                extraction_temp_dir = None
                try:
                    package_data_hex = data['data']
                    package_data_bytes = bytes.fromhex(package_data_hex)

                    received_zip_path = os.path.join(package_receive_temp_dir, 'received_package.zip')
                    with open(received_zip_path, 'wb') as f:
                        f.write(package_data_bytes)
                    
                    extraction_temp_dir, metadata = self.unpack_files(received_zip_path)
                    
                    original_base_filename = metadata.get('original_filename', 'decrypted_file')
                    algo = metadata.get('encryption_type', 'AES') 

                    enc_file_name_in_zip = None
                    rsa_key_name_in_zip = None
                    sig_name_in_zip = None

                    for item in os.listdir(extraction_temp_dir):
                        if item.endswith(f'.{algo}.enc'): 
                            enc_file_name_in_zip = item
                        elif item.endswith(f'.{algo}.key.txt.rsa'): 
                            rsa_key_name_in_zip = item
                        elif item.endswith(f'.{algo}.enc.sha256sig'): 
                            sig_name_in_zip = item
                    
                    if not all([enc_file_name_in_zip, rsa_key_name_in_zip, sig_name_in_zip]):
                        raise FileNotFoundError("解压后的文件中未能找到所有必需的文件 (加密文件、RSA密钥、签名)。")

                    rsa_key_path = os.path.join(extraction_temp_dir, rsa_key_name_in_zip)
                    enc_file_path = os.path.join(extraction_temp_dir, enc_file_name_in_zip)
                    sig_path = os.path.join(extraction_temp_dir, sig_name_in_zip)

                    with open(rsa_key_path, 'rb') as f:
                        rsa_encrypted_key = f.read()
                    key = self.rsa.decrypt(rsa_encrypted_key) 
                    
                    with open(enc_file_path, 'rb') as f:
                        encrypted_file_data = f.read()
                    
                    cipher = AES(key) if algo == 'AES' else DES(key)
                    block_size = 16 if algo == 'AES' else 8
                    
                    decrypted_data = b''
                    for i in range(0, len(encrypted_file_data), block_size):
                        block = encrypted_file_data[i:i+block_size]
                        decrypted_data += cipher.decrypt(block)
                    decrypted_data = self.pkcs7_unpad(decrypted_data) 
                    
                    hash_of_encrypted_file = hashlib.sha256(encrypted_file_data).digest()
                    with open(sig_path, 'rb') as f:
                        signature = f.read()
                    
                    sender_public_key_pem = self.identity_manager.get_trusted_peer_pubkey_pem(peer_uuid)
                    if not sender_public_key_pem:
                        raise Exception(f"无法获取邻居 {peer_uuid[:8]} 的信任公钥，无法验证签名。")
                    
                    temp_rsa_verifier = RSA()
                    temp_rsa_verifier.set_public_key_from_pem(sender_public_key_pem) 
                    
                    if not temp_rsa_verifier.verify(hash_of_encrypted_file, signature): 
                        raise Exception("签名验证失败! 文件可能被篡改或来自不受信任的发送方。")
                    
                    save_path, _ = QFileDialog.getSaveFileName(
                        self, "保存解密文件", original_base_filename 
                    )
                    if save_path:
                        with open(save_path, 'wb') as f:
                            f.write(decrypted_data)
                        self.receive_status_label.setText("文件接收完成")
                        self.receive_status_label.setStyleSheet("""
                            color: #4CAF50; 
                            font-weight: bold;
                            padding: 10px;
                            background-color: #e8f5e9;
                            border-radius: 5px;
                            border: 1px solid #81c784;
                        """)
                        self.status_tip_label.setText(f"文件 '{os.path.basename(save_path)}' 已成功接收、验证并解密保存。")
                        QMessageBox.information(self, "文件接收成功", f"文件 '{os.path.basename(save_path)}' 已成功接收、验证并解密保存。")
                    else:
                        self.receive_status_label.setText("文件接收已取消")
                        self.receive_status_label.setStyleSheet("""
                            color: #f44336; 
                            font-weight: bold;
                            padding: 10px;
                            background-color: #ffebee;
                            border-radius: 5px;
                            border: 1px solid #e57373;
                        """)
                        self.status_tip_label.setText("文件解密成功，但未保存。")
                        QMessageBox.warning(self.parent(), "操作取消", "文件解密成功，但未保存。")

                except ValueError as ve: 
                    QMessageBox.critical(self, "数据错误", f"处理接收数据失败: {str(ve)}")
                except FileNotFoundError as fnfe:
                    QMessageBox.critical(self, "文件错误", f"处理接收数据失败: {str(fnfe)}")
                except Exception as e:
                    QMessageBox.critical(self.parent_window, "处理错误", f"处理接收数据失败: {repr(e)}") 
                finally:
                    if package_receive_temp_dir and os.path.exists(package_receive_temp_dir):
                        shutil.rmtree(package_receive_temp_dir)
                    if extraction_temp_dir and os.path.exists(extraction_temp_dir):
                        shutil.rmtree(extraction_temp_dir)
                    self.progress_bar.setVisible(False)
                    self.progress_bar.setRange(0,100) 
            elif data.get('type') == MSG_TYPE_FILE_TRANSFER: 
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 100) 
                
                metadata = data.get('metadata', {})
                encrypted_file_data_hex = data.get('encrypted_file_data')
                encrypted_symmetric_key_hex = data.get('encrypted_symmetric_key')
                signature_hex = data.get('signature')
                sender_uuid_from_msg = data.get('sender_uuid')

                if not all([metadata, encrypted_file_data_hex, encrypted_symmetric_key_hex, signature_hex, sender_uuid_from_msg]):
                    raise ValueError("文件传输消息内容不完整。")

                if sender_uuid_from_msg != peer_uuid:
                    raise Exception("消息发送者 UUID 与会话 UUID 不匹配，存在安全风险！")

                sender_public_key_pem = self.identity_manager.get_trusted_peer_pubkey_pem(sender_uuid_from_msg)
                if not sender_public_key_pem:
                    raise Exception(f"无法获取发送方 {sender_uuid_from_msg[:8]} 的信任公钥，无法验证签名和解密。")
                
                encrypted_file_data_bytes = bytes.fromhex(encrypted_file_data_hex)
                file_hash = hashlib.sha256(encrypted_file_data_bytes).digest()
                signature_bytes = bytes.fromhex(signature_hex)

                temp_rsa_verifier = RSA()
                temp_rsa_verifier.set_public_key_from_pem(sender_public_key_pem) 
                if not temp_rsa_verifier.verify(file_hash, signature_bytes):
                    raise Exception("文件签名验证失败！文件可能被篡改或来自非信任来源。")
                print("DEBUG: 文件签名验证成功。")

                encrypted_symmetric_key_bytes = bytes.fromhex(encrypted_symmetric_key_hex)
                symmetric_key = self.rsa.decrypt(encrypted_symmetric_key_bytes) 

                algo = metadata.get('encryption_type', 'AES')
                cipher = AES(symmetric_key) if algo == 'AES' else DES(symmetric_key)
                block_size = 16 if algo == 'AES' else 8

                decrypted_file_data = b''
                total_len = len(encrypted_file_data_bytes)
                if total_len == 0:
                    decrypted_file_data = b''
                else:
                    for i in range(0, total_len, block_size):
                        block = encrypted_file_data_bytes[i:i+block_size]
                        decrypted_file_data += cipher.decrypt(block)
                        self.progress_bar.setValue(int(((i+block_size) / total_len) * 100) if total_len > 0 else 0)
                decrypted_file_data = self.pkcs7_unpad(decrypted_file_data)
                self.progress_bar.setValue(100)
                print("DEBUG: 文件数据解密成功。")

                original_filename = metadata.get('original_filename', 'decrypted_file')
                save_path, _ = QFileDialog.getSaveFileName(self, "保存接收文件", original_filename)
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(decrypted_file_data)
                    self.receive_status_label.setText("文件接收完成")
                    self.receive_status_label.setStyleSheet("""
                        color: #4CAF50; 
                        font-weight: bold;
                        padding: 10px;
                        background-color: #e8f5e9;
                        border-radius: 5px;
                        border: 1px solid #81c784;
                    """)
                    self.status_tip_label.setText(f"文件 '{os.path.basename(save_path)}' 已成功接收、验证并解密保存。")
                    QMessageBox.information(self, "文件接收成功", f"文件 '{os.path.basename(save_path)}' 已成功接收、验证并解密保存。")
                else:
                    self.receive_status_label.setText("文件接收已取消")
                    self.receive_status_label.setStyleSheet("""
                        color: #f44336; 
                        font-weight: bold;
                        padding: 10px;
                        background-color: #ffebee;
                        border-radius: 5px;
                        border: 1px solid #e57373;
                    """)
                    self.status_tip_label.setText("文件解密成功，但未保存。")
                    QMessageBox.warning(self.parent(), "操作取消", "文件解密成功，但未保存。") 

            else:
                print(f"DEBUG: 收到未知类型的消息: {data.get('type')}")
        except json.JSONDecodeError:
            print(f"DEBUG: 无法解析接收到的消息为 JSON: {message_str[:100]}...")
        except Exception as e:
            QMessageBox.critical(self.parent(), "处理接收文件错误", f"处理接收文件失败: {repr(e)}") 
        finally:
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(0)

    def closeEvent(self, event):
        if hasattr(self, 'udp_discovery_thread') and self.udp_discovery_thread and self.udp_discovery_thread.isRunning():
            print("DEBUG: 正在停止UDP发现线程...")
            self.udp_discovery_thread.stop()
            self.udp_discovery_thread.wait(2000) 

        if hasattr(self, 'tcp_listener_thread') and self.tcp_listener_thread and self.tcp_listener_thread.isRunning():
            print("DEBUG: 正在停止TCP监听线程...")
            self.tcp_listener_thread.stop()
            self.tcp_listener_thread.wait(2000)

        for uuid_key, session_thread in list(self.active_p2p_sessions.items()): 
            if session_thread and session_thread.isRunning():
                print(f"DEBUG: 正在停止 P2P 会话线程 {uuid_key[:8] if isinstance(uuid_key, str) else uuid_key}...")
                session_thread.stop()
                session_thread.wait(2000)

        if hasattr(self, 'peer_cleanup_timer') and self.peer_cleanup_timer.isActive():
            self.peer_cleanup_timer.stop()

        event.accept()

    def select_enc_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件", filter="所有文件 (*.*)")
        if file_name: 
            self.enc_file_label.setText(file_name)
            self._update_send_button_status() 

    def encrypt_file(self):
        try:
            file_path = self.enc_file_label.text()
            if file_path == '未选择文件': raise Exception("请先选择文件")
            algo = self.enc_algo_combo.currentText()
            key_len = 32 if algo == 'AES' else 8 
            key = os.urandom(key_len)
            
            base_dir = os.path.dirname(file_path)
            file_basename = os.path.basename(file_path)
            key_txt_path = os.path.join(base_dir, f"{file_basename}.{algo}.key.txt")
            enc_out_path = os.path.join(base_dir, f"{file_basename}.{algo}.enc")

            with open(key_txt_path, 'w') as f: f.write(key.hex())
            with open(file_path, 'rb') as f: data = f.read()
            
            cipher = AES(key) if algo == 'AES' else DES(key)
            block_size = 16 if algo == 'AES' else 8
            data_padded = self.pkcs7_pad(data, block_size)
            
            encrypted_data = b''
            for i in range(0, len(data_padded), block_size):
                encrypted_data += cipher.encrypt(data_padded[i:i+block_size])
            
            with open(enc_out_path, 'wb') as f: f.write(encrypted_data)
            self.enc_key_path_label.setText(f'明文密钥txt路径: {key_txt_path}')
            self.enc_out_path_label.setText(f'加密文件路径: {enc_out_path}')
            QMessageBox.information(self.parent(), "成功", f"{algo} 加密完成。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"加密过程中出错：{str(e)}") 

    def select_key_enc_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择明文密钥txt", filter="密钥文件 (*.key.txt)")
        if file_name: self.key_enc_file_label.setText(file_name)

    def key_encrypt(self):
        try:
            key_txt_path = self.key_enc_file_label.text()
            if key_txt_path == '未选择明文密钥txt': raise Exception("请先选择明文密钥txt")
            with open(key_txt_path, 'r') as f:
                key = bytes.fromhex(f.read().strip())
            rsa_encrypted_key = self.rsa.encrypt(key) 
            rsa_key_path = key_txt_path + '.rsa'
            with open(rsa_key_path, 'wb') as f: f.write(rsa_encrypted_key)
            self.key_enc_out_path_label.setText(f'RSA加密密钥文件路径: {rsa_key_path}')
            QMessageBox.information(self.parent(), "成功", "密钥加密完成。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"密钥加密过程中出错：{str(e)}") 

    def select_sign_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择加密文件", filter="加密文件 (*.enc)")
        if file_name: self.sign_file_label.setText(file_name)

    def sign_file(self):
        try:
            file_path = self.sign_file_label.text()
            if file_path == '未选择文件': raise Exception("请先选择文件")
            with open(file_path, 'rb') as f: data = f.read()
            hash_of_data = hashlib.sha256(data).digest()
            signature = self.rsa.sign(hash_of_data) 
            sign_path = file_path + '.sha256sig'
            with open(sign_path, 'wb') as f: f.write(signature)
            self.sign_path_label.setText(f'签名文件路径: {sign_path}')
            QMessageBox.information(self.parent(), "成功", "文件签名完成。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"签名过程中出错：{str(e)}") 

    def select_auth_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择加密文件", filter="加密文件 (*.enc)")
        if file_name: self.auth_file_label.setText(file_name)

    def select_auth_sig(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择签名文件", filter="签名文件 (*.sha256sig)")
        if file_name: self.auth_sig_label.setText(file_name)

    def auth_verify(self):
        try:
            file_path = self.auth_file_label.text()
            sig_path = self.auth_sig_label.text()
            if file_path == '未选择原始文件' or sig_path == '未选择签名文件':
                raise Exception("请先选择原始文件和签名文件")
            with open(file_path, 'rb') as f: data = f.read()
            hash_of_data = hashlib.sha256(data).digest()
            with open(sig_path, 'rb') as f: signature = f.read()
            result = self.rsa.verify(hash_of_data, signature) 
            self.auth_result_label.setText(f'认证结果: {"签名有效" if result else "签名无效"}')
            QMessageBox.information(self.parent(), "认证", f"认证结果: {'签名有效' if result else '签名无效'}") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"认证过程中出错：{str(e)}") 

    def select_key_dec_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择RSA加密密钥文件", filter="RSA密钥文件 (*.rsa)")
        if file_name: self.key_dec_file_label.setText(file_name)

    def key_decrypt(self):
        try:
            rsa_key_path = self.key_dec_file_label.text()
            if rsa_key_path == '未选择RSA加密密钥文件': raise Exception("请先选择RSA加密密钥文件")
            with open(rsa_key_path, 'rb') as f: rsa_encrypted_key = f.read()
            key = self.rsa.decrypt(rsa_encrypted_key) 
            key_txt_path = rsa_key_path.replace('.rsa', '.decrypted.txt')
            with open(key_txt_path, 'w') as f: f.write(key.hex())
            self.key_dec_out_path_label.setText(f'明文密钥txt路径: {key_txt_path}')
            QMessageBox.information(self.parent(), "成功", "密钥解密完成。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"密钥解密过程中出错：{str(e)}") 

    def select_file_dec_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择加密文件", filter="加密文件 (*.enc)")
        if file_name: self.file_dec_file_label.setText(file_name)

    def select_file_dec_key(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择明文密钥txt", filter="密钥文件 (*.decrypted.txt)")
        if file_name: self.file_dec_key_label.setText(file_name)

    def file_decrypt(self):
        try:
            file_path = self.file_dec_file_label.text()
            key_path = self.file_dec_key_label.text()
            if file_path == '未选择加密文件' or key_path == '未选择明文密钥txt':
                raise Exception("请先选择加密文件和明文密钥txt")
            algo = self.file_dec_algo_combo.currentText()
            with open(key_path, 'r') as f: key = bytes.fromhex(f.read().strip())
            with open(file_path, 'rb') as f: encrypted_data = f.read()
            
            cipher = AES(key) if algo == 'AES' else DES(key)
            block_size = 16 if algo == 'AES' else 8
            decrypted_data = b''
            for i in range(0, len(encrypted_data), block_size):
                block = encrypted_data[i:i+block_size]
                decrypted_data += cipher.decrypt(block)
            decrypted_data = self.pkcs7_unpad(decrypted_data)
            
            dec_out_path = file_path + f'.{algo}.dec'
            with open(dec_out_path, 'wb') as f: f.write(decrypted_data)
            
            original_name = file_path.replace(f'.{algo}.enc', '')
            if original_name and os.path.basename(original_name):
                with open(original_name, 'wb') as f: f.write(decrypted_data)
                self.file_dec_out_path_label.setText(f'解密文件路径: {dec_out_path}\n原始文件名解密文件路径: {original_name}')
            else:
                self.file_dec_out_path_label.setText(f'解密文件路径: {dec_out_path}\n(无法推断原始文件名，未创建)')
            
            QMessageBox.information(self.parent(), "成功", "文件解密完成。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"解密过程中出错：{str(e)}") 

    def pkcs7_pad(self, data, block_size):
        if not isinstance(data, bytes): raise TypeError("数据必须是字节类型才能进行填充")
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    def pkcs7_unpad(self, data):
        if not data: raise ValueError("数据为空，无法去除填充")
        pad_len = data[-1]
        if not (1 <= pad_len <= len(data) and pad_len <= 16): 
            raise ValueError(f"填充长度无效: {pad_len}。可能数据已损坏或未正确填充。")
        
        expected_padding = bytes([pad_len] * pad_len)
        if data[-pad_len:] != expected_padding:
            raise ValueError("填充内容无效 (PKCS#7 验证失败)。数据可能已损坏。")
        return data[:-pad_len]

    def generate_new_keypair(self):
        self.identity_manager._create_new_rsa_identity_keys()
        self._my_public_key_pem = self.identity_manager.get_my_public_key_pem()
        self.my_fingerprint_label.setText(f"<b>公钥指纹:</b> {self.get_my_public_key_fingerprint()[:16]}...")

    def export_public_key(self):
        try:
            file_name, _ = QFileDialog.getSaveFileName(self, "导出公钥", "", "公钥文件 (*.pub)")
            if file_name:
                public_pem = self.identity_manager.get_my_public_key_pem()
                if public_pem:
                    with open(file_name, 'wb') as f:
                        f.write(public_pem)
                    QMessageBox.information(self.parent(), "成功", "公钥导出成功") 
                else:
                    QMessageBox.warning(self.parent(), "警告", "当前没有有效的公钥可导出。") 
        except Exception as e:
            QMessageBox.critical(self.parent(), "错误", f"导出公钥失败: {str(e)}") 

    def export_private_key(self):
        self.identity_manager.export_private_key_to_file()
    def import_trusted_peer_public_key(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "导入信任公钥", "", "公钥文件 (*.pub)")
        if not file_name:
            return
        with open(file_name, 'rb') as f:
            public_pem = f.read()
        # 让用户输入对方昵称或UUID
        peer_name, ok = QInputDialog.getText(self, "输入对方昵称/ID", "请输入对方昵称或唯一标识：")
        if not ok or not peer_name:
            return
        # 计算指纹作为UUID（可选）
        peer_uuid = self.identity_manager.get_fingerprint_from_pem(public_pem)
        # 添加到trusted_peers.json
        self.identity_manager.add_trusted_peer(peer_uuid, peer_name, public_pem.decode('utf-8'))
        QMessageBox.information(self, "导入成功", f"已将 {peer_name} 的公钥导入到 trusted_peers.json")

    def import_public_key(self):
        self.identity_manager.import_public_key_from_file()
        self._my_public_key_pem = self.identity_manager.get_my_public_key_pem()
        self.my_fingerprint_label.setText(f"<b>公钥指纹:</b> {self.get_my_public_key_fingerprint()[:16]}...")

    def import_private_key(self):
        self.identity_manager.import_private_key_from_file()
        self._my_public_key_pem = self.identity_manager.get_my_public_key_pem()
        self.my_fingerprint_label.setText(f"<b>公钥指纹:</b> {self.get_my_public_key_fingerprint()[:16]}...")


    def select_file_to_send(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件", filter="所有文件 (*.*)")
        if file_name: 
            self.selected_file_label.setText(file_name)
            self._update_send_button_status() 

    def quick_send(self):
        if not self.selected_file_label.text() or self.selected_file_label.text() == "未选择文件":
            QMessageBox.warning(self.parent(), "发送错误", "请先选择要发送的文件。") 
            return
        
        selected_items = self.peers_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.parent(), "发送错误", "请从'发现的邻居'列表中选择一个接收方。")
            return
        
        selected_peer_uuid = selected_items[0].data(Qt.UserRole)
        target_session = self.active_p2p_sessions.get(selected_peer_uuid)

        if not target_session or not target_session.is_connected:
            QMessageBox.warning(self.parent(), "发送错误", "选定的邻居未连接或连接不稳定，请重新连接。") 
            return
        
        recipient_public_key_pem = self.identity_manager.get_trusted_peer_pubkey_pem(selected_peer_uuid)
        if not recipient_public_key_pem:
            QMessageBox.warning(self.parent(), "发送错误", "无法获取接收方信任的公钥，请先进行信任验证。") 
            return

        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(10)
            self.status_tip_label.setText("正在准备发送文件...")

            file_path = self.selected_file_label.text()
            algo = 'AES' 
            key_bytes = os.urandom(32) 

            temp_rsa_encryptor = RSA()
            try:
                e_val, n_val = RSA.get_e_n_from_pem(recipient_public_key_pem) # 假设有静态方法
                temp_rsa_encryptor.set_public_key(e_val, n_val)
            except Exception as e_pem:
                 raise Exception(f"无法从PEM设置接收方公钥: {e_pem}")

            rsa_encrypted_key_data = temp_rsa_encryptor.encrypt(key_bytes) 
            
            with open(file_path, 'rb') as f: data = f.read()
            cipher = AES(key_bytes) 
            block_size = 16 
            data_padded = self.pkcs7_pad(data, block_size)
            encrypted_file_data = b''
            for i in range(0, len(data_padded), block_size):
                encrypted_file_data += cipher.encrypt(data_padded[i:i+block_size])
            self.progress_bar.setValue(30)

            hash_of_encrypted_data = hashlib.sha256(encrypted_file_data).digest()
            signature_data = self.rsa.sign(hash_of_encrypted_data) 
            self.progress_bar.setValue(50)

            original_filename = os.path.basename(file_path)
            message_payload = {
                'type': MSG_TYPE_FILE_TRANSFER, 
                'metadata': {
                    'original_filename': original_filename,
                    'encryption_type': algo,
                    'file_size': len(encrypted_file_data) 
                },
                'encrypted_file_data': encrypted_file_data.hex(), 
                'encrypted_symmetric_key': rsa_encrypted_key_data.hex(), 
                'signature': signature_data.hex(), 
                'sender_uuid': self.my_uuid 
            }
            json_to_send = json.dumps(message_payload).encode('utf-8')
            self.progress_bar.setValue(80)
            
            if not target_session.send_data_to_peer(json_to_send):
                raise Exception("通过网络线程发送文件数据失败。")
            self.progress_bar.setValue(100)
            self.status_tip_label.setText(f"文件已成功发送给 {target_session.peer_nickname}")
            QMessageBox.information(self, "成功", f"文件已成功发送给 {target_session.peer_nickname}。")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.status_tip_label.setText(f"发送失败: {str(e)}")
            QMessageBox.critical(self.parent(), "发送失败", f"文件发送过程中出错: {repr(e)}") 
        finally:
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(0)

    def quick_receive_setup(self):
        self.receive_status_label.setText("正在等待接收文件...")
        self.receive_status_label.setStyleSheet("""
            color: #2196F3; 
            font-weight: bold;
            padding: 10px;
            background-color: #e3f2fd;
            border-radius: 5px;
            border: 1px solid #90caf9;
        """)
        self.status_tip_label.setText("提示：当收到文件时，系统会自动提示您保存。")
        QMessageBox.information(self.parent(), "接收模式", "已进入接收模式，程序将自动接收文件。\n收到文件时会提示您保存。")
        self.progress_bar.setVisible(False)

    def _update_send_button_status(self):
        """
        根据是否选择了文件、是否选择了邻居以及所选邻居是否已连接且受信任，
        来更新"一键发送"按钮的启用状态。
        """
        file_selected = False
        if hasattr(self, 'selected_file_label') and self.selected_file_label.text() != "未选择文件" and \
           self.selected_file_label.text() is not None and \
           os.path.exists(self.selected_file_label.text()):
            file_selected = True

        peer_selected_and_ready = False
        selected_items = self.peers_list_widget.selectedItems()

        if selected_items:
            selected_peer_item = selected_items[0]
            peer_uuid = selected_peer_item.data(Qt.UserRole)

            if peer_uuid:
                # 检查邻居是否有活动的、已连接的会话
                session_thread = self.active_p2p_sessions.get(peer_uuid)
                if session_thread and session_thread.is_connected:
                    # 检查邻居是否受信任
                    if self.identity_manager.is_peer_trusted(peer_uuid):
                        peer_selected_and_ready = True
        
        print(f"DEBUG: 按钮状态更新 - 文件已选: {file_selected}, 邻居已选且就绪: {peer_selected_and_ready}")
        
        if hasattr(self, 'send_btn'):
            self.send_btn.setEnabled(file_selected and peer_selected_and_ready)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileEncryptionApp()
    ex.show() 
    ex._post_init_setup() 
    sys.exit(app.exec_())

