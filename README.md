# 安全文件传输工具

这是一个基于PyQt5开发的安全文件传输应用程序，支持P2P通信，文件加密/解密，以及数字签名功能。

## 项目目录结构

```
C:.
│  aes_encryption.py        # AES加密算法实现
│  build.bat                # 打包脚本
│  config.json              # 应用程序配置文件
│  des_encryption.py        # DES加密算法实现
│  icon.ico                 # 应用图标
│  identity_manager.py      # 身份和密钥管理
│  main.py                  # 主程序入口和GUI实现
│  my_identity_keys.json    # 用户身份密钥存储
│  network_core.py          # 网络通信核心组件
│  README.md                # 项目说明文档(本文件)
│  rsa_encryption.py        # RSA加密算法实现
│  trusted_peers.json       # 受信任节点列表
│  安全文件传输工具.spec    # PyInstaller打包配置
│  测试记录.md              # 测试和开发记录
│  
├─build                     # 构建过程中生成的文件
│  └─安全文件传输工具
│      │  Analysis-00.toc
│      │  base_library.zip
│      │  EXE-00.toc
│      │  PKG-00.toc
│      │  PYZ-00.pyz
│      │  PYZ-00.toc
│      │  warn-安全文件传输工具.txt
│      │  xref-安全文件传输工具.html
│      │  安全文件传输工具.pkg
│      │  
│      └─localpycs
│              pyimod01_archive.pyc
│              pyimod02_importers.pyc
│              pyimod03_ctypes.pyc
│              pyimod04_pywin32.pyc
│              struct.pyc
│
├─dist                      # 发布版本目录
│      安全文件传输工具.exe # 可执行程序
│
└─__pycache__               # Python编译缓存
        aes_encryption.cpython-39.pyc
        des_encryption.cpython-39.pyc
        identity_manager.cpython-39.pyc
        network_core.cpython-39.pyc
        rsa_encryption.cpython-39.pyc
```

## 核心文件说明

### 1. main.py (58KB, 1182行)
- 项目的主要程序入口文件
- 实现了图形用户界面(GUI)和主要的文件加密/解密功能
- 包含`FileEncryptionApp`类，管理P2P通信、加密解密和文件传输
- 实现了一键操作、文件加密、密钥加密、SHA+RSA签名、认证、密钥解密和文件解密等功能

### 2. network_core.py (21KB, 465行)
- 实现网络通信的核心组件
- 包含P2P连接(`P2PConnectionThread`)、UDP发现(`UDPDiscoveryThread`)和TCP监听(`TCPListenerThread`)的线程类
- 管理局域网内节点发现、连接建立和数据传输

### 3. identity_manager.py (20KB, 428行)
- 管理用户身份和密钥的类
- 处理RSA密钥对的生成、加载和存储
- 实现TOFU (Trust On First Use) 信任机制
- 管理受信任伙伴的公钥和身份信息

### 4. rsa_encryption.py (3.7KB, 130行)
- RSA加密算法实现
- 提供公钥/私钥加密、解密和签名相关功能
- 支持密钥的PEM格式导入导出

### 5. aes_encryption.py (9.2KB, 185行)
- AES加密算法实现
- 提供对称加密/解密功能
- 实现ECB模式加密

### 6. des_encryption.py (7.2KB, 229行)
- DES加密算法实现
- 提供另一种对称加密/解密方案
- 实现ECB模式加密

### 7. 其他配置和数据文件
- **trusted_peers.json**: 存储受信任的P2P伙伴信息
- **my_identity_keys.json**: 存储当前用户的身份和RSA密钥信息
- **config.json**: 存储如UUID和昵称等基本身份信息
- **build.bat**: Windows下构建可执行程序的批处理脚本
- **安全文件传输工具.spec**: PyInstaller打包配置文件

## 系统特点

1. **P2P安全通信**
   - 局域网节点自动发现
   - TOFU信任机制进行身份验证
   - 基于RSA的密钥交换确保通信安全

2. **加密和签名功能**
   - 支持AES和DES两种对称加密算法
   - 实现RSA非对称加密保护对称密钥
   - 提供数字签名和验证功能确保文件完整性

3. **身份和密钥管理**
   - 用户身份生成和管理
   - RSA密钥对的生成、导入和导出
   - 安全存储用户的私钥和信任伙伴的公钥

4. **用户友好界面**
   - 基于PyQt5构建的图形界面
   - 支持拖放操作和一键操作
   - 进度条显示传输和处理进度

## 使用说明

1. **运行程序**
   - 双击`dist/安全文件传输工具.exe`或通过命令行运行`python main.py`

2. **连接到节点**
   - 程序启动后会自动发现局域网内其他节点
   - 双击"发现的邻居"列表中的节点进行连接
   - 首次连接时会要求验证对方身份（TOFU验证）

3. **发送文件**
   - 连接建立后，选择要发送的文件
   - 点击"一键发送"完成加密、签名和传输

4. **接收文件**
   - 接收方会自动处理接收到的文件
   - 验证签名、解密并保存到指定位置

## 技术实现

该项目采用模块化设计，将不同功能分离到独立的Python文件中，使代码结构清晰，便于维护和扩展。核心技术包括：

- PyQt5实现跨平台GUI
- 自定义实现的AES, DES和RSA加密算法
- 基于UDP广播的局域网节点发现
- 基于TCP的稳定数据传输
- RSA公钥加密保护会话密钥
- SHA256+RSA组合实现数字签名 