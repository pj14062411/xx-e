# 文件加密传输系统完整流程图

## 1. 程序初始化和身份管理

```mermaid
graph TD
    %% 程序初始化
    A["程序启动 (main.py:28)"] --> B["初始化FileEncryptionApp"]
    B --> C["初始化UI (main.py:90)"]
    B --> D["初始化网络组件"]
    B --> E["初始化加密组件"]

    %% 身份初始化流程
    F["身份初始化 (identity_manager.py:48)"] --> F1["load_or_create_identity"]
    F1 --> F2{"config.json存在?"}
    F2 -->|是| F3["加载现有身份"]
    F2 -->|否| F4["创建新身份 (_create_new_identity)"]
    F4 --> F5["生成UUID (uuid.uuid4())"]
    F4 --> F6["设置用户昵称 (QInputDialog.getText)"]
    F4 --> F7["保存到config.json (json.dump)"]

    %% RSA密钥初始化流程
    G["RSA密钥初始化 (identity_manager.py:82)"] --> G1["load_or_create_rsa_identity_keys"]
    G1 --> G2{"my_identity_keys.json存在?"}
    G2 -->|是| G3["加载现有密钥"]
    G2 -->|否| G4["创建新密钥 (_create_new_rsa_identity_keys)"]
    G3 --> G3.1["输入密码 (QInputDialog.getText)"]
    G3.1 --> G3.2["解密私钥 (_decrypt_private_key_exponent)"]
    G4 --> G4.1["生成2048位RSA密钥对 (rsa.generate_private_key)"]
    G4.1 --> G4.2["设置密码 (QInputDialog.getText)"]
    G4.2 --> G4.3["加密私钥 (_encrypt_private_key_exponent)"]
    G4.3 --> G4.4["保存到my_identity_keys.json (json.dump)"]

    %% 私钥加密流程
    H["私钥加密 (identity_manager.py:249)"] --> H1["生成随机盐值 (os.urandom(16))"]
    H1 --> H2["PBKDF2密钥派生 (PBKDF2HMAC)"]
    H2 --> H3["生成随机IV (os.urandom(16))"]
    H3 --> H4["AES-256-CBC加密 (Cipher)"]
    H4 --> H5["PKCS7填充 (padding.PKCS7)"]
    H5 --> H6["保存加密数据"]
```

## 2. 文件传输和加密操作

```mermaid
graph TD
    %% 文件传输流程
    L["文件传输 (main.py:1545)"] --> L1["选择文件 (select_file_to_send)"]
    L1 --> L2["生成随机会话密钥 (os.urandom(32))"]
    L2 --> L3["使用AES加密文件"]
    L3 --> L4["使用RSA加密会话密钥"]
    L4 --> L5["计算文件哈希 (hashlib.sha256)"]
    L5 --> L6["数字签名 (rsa.sign)"]
    L6 --> L7["发送数据包"]
    L7 --> L8["接收方验证签名"]
    L8 --> L9["解密会话密钥"]
    L9 --> L10["解密文件"]

    %% 加密操作流程
    M["加密操作"] --> M1["RSA操作 (rsa_encryption.py:5)"]
    M --> M2["AES操作 (aes_encryption.py:1)"]
    M --> M3["DES操作 (des_encryption.py:1)"]

    M1 --> M1.1["公钥加密 (encrypt)"]
    M1 --> M1.2["私钥解密 (decrypt)"]
    M1 --> M1.3["数字签名 (sign)"]
    M1 --> M1.4["签名验证 (verify)"]

    M2 --> M2.1["密钥扩展 (_key_expansion)"]
    M2 --> M2.2["字节替换 (_sub_bytes)"]
    M2 --> M2.3["行移位 (_shift_rows)"]
    M2 --> M2.4["列混合 (_mix_columns)"]
    M2 --> M2.5["轮密钥加 (_add_round_key)"]

    %% 加密操作详细流程
    subgraph AES加密流程
        A1["初始化AES (key_size=32)"] --> A2["密钥扩展"]
        A2 --> A3["数据分块"]
        A3 --> A4["加密操作"]
        A4 --> A5["合并结果"]
    end

    subgraph RSA加密流程
        R1["初始化RSA (key_size=2048)"] --> R2["密钥对生成"]
        R2 --> R3["公钥加密"]
        R2 --> R4["私钥解密"]
        R2 --> R5["数字签名"]
    end
```

## 3. 网络发现和连接管理

```mermaid
graph TD
    %% 网络发现流程
    N["网络发现 (network_core.py:48)"] --> N1["创建UDP Socket"]
    N1 --> N2["绑定广播端口"]
    N2 --> N3["启动发现线程"]
    N3 --> N4["发送广播包"]
    N4 --> N5["接收响应"]
    N5 --> N6["更新节点列表"]

    %% TCP监听流程
    T["TCP监听 (main.py:718)"] --> T1["创建TCP Socket"]
    T1 --> T2["绑定监听端口"]
    T2 --> T3["启动监听线程"]
    T3 --> T4["接受连接"]
    T4 --> T5["处理新连接"]

    %% P2P连接流程
    P["P2P连接 (network_core.py:106)"] --> P1["建立TCP连接"]
    P1 --> P2["交换公钥"]
    P2 --> P3["TOFU验证"]
    P3 --> P4["建立加密通道"]
```

## 4. 安全验证流程

```mermaid
graph TD
    %% TOFU验证流程
    V["TOFU验证 (main.py:841)"] --> V1["获取对方公钥指纹"]
    V1 --> V2{"是否已信任?"}
    V2 -->|是| V3["验证指纹匹配"]
    V2 -->|否| V4["显示指纹确认对话框"]
    V4 --> V5{"用户确认?"}
    V5 -->|是| V6["保存为信任节点"]
    V5 -->|否| V7["拒绝连接"]

    %% 公钥指纹验证
    F["公钥指纹验证"] --> F1["计算SHA256哈希"]
    F1 --> F2["转换为十六进制"]
    F2 --> F3["显示给用户"]
```

## 5. 错误处理流程

```mermaid
graph TD
    %% 错误处理流程
    E["错误处理"] --> E1["网络错误"]
    E --> E2["加密错误"]
    E --> E3["文件操作错误"]

    E1 --> E1.1["连接超时"]
    E1 --> E1.2["数据包丢失"]
    E1 --> E1.3["连接断开"]

    E2 --> E2.1["密钥不匹配"]
    E2 --> E2.2["签名验证失败"]
    E2 --> E2.3["解密失败"]

    E3 --> E3.1["文件不存在"]
    E3 --> E3.2["权限不足"]
    E3 --> E3.3["磁盘空间不足"]
```

## 说明

这些流程图展示了文件加密传输系统的完整架构和流程：

1. **程序初始化和身份管理**：
   - 展示了程序启动、UI初始化、网络和加密组件的初始化过程
   - 详细说明了身份初始化流程，包括UUID生成和用户昵称设置
   - 展示了RSA密钥的创建和管理流程
   - 说明了私钥加密的具体步骤

2. **文件传输和加密操作**：
   - 展示了完整的文件传输流程，从文件选择到最终解密
   - 详细说明了各种加密操作（RSA、AES、DES）的具体实现
   - 包含了AES和RSA加密的详细子流程

3. **网络发现和连接管理**：
   - 展示了UDP发现机制
   - 说明了TCP监听和连接处理流程
   - 详细描述了P2P连接的建立过程

4. **安全验证流程**：
   - 展示了TOFU（Trust On First Use）验证机制
   - 说明了公钥指纹验证过程
   - 包含了用户确认和信任管理

5. **错误处理流程**：
   - 展示了各类错误的处理机制
   - 包括网络、加密和文件操作相关的错误处理
   - 说明了错误恢复和用户通知机制

每个流程图都包含了具体的代码位置和实现细节，便于理解和追踪代码实现。这些流程图共同构成了系统的完整架构视图，有助于理解系统的工作原理和各个组件之间的交互关系。 