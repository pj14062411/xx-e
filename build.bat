@echo off
chcp 65001 >nul
echo 开始打包安全文件传输工具 (基础库版本)...

rem --- 确保 Conda 环境激活 ---
echo 正在激活 Conda 环境 'secure_transfer'...
call conda activate secure_transfer
if errorlevel 1 (
    echo 错误：无法激活 Conda 环境 'secure_transfer'。请确保该环境已正确创建和配置。
    pause
    exit /b 1
)

rem --- 安装核心依赖 ---
echo 正在安装/更新核心依赖 (PyQt5, cryptography, pycryptodome)...
echo 注意：如果你的自定义加密模块不依赖 cryptography 或 pycryptodome，可以从这里移除。
pip install -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple PyQt5==5.15.9 cryptography==41.0.7 pycryptodome==3.19.0
if errorlevel 1 (
    echo 错误：核心依赖安装失败。
    pause
    exit /b 1
)

rem --- 不再需要 netifaces 或 psutil 的安装步骤 ---
rem --- 也不再需要动态创建 temp_main.py ---

echo 开始使用 PyInstaller 打包 (基于 '安全文件传输工具.spec')...
rem --clean 会在打包前清除旧的 build 和 dist 目录
rem --noconfirm 会自动确认覆盖旧文件
pyinstaller --noconfirm --clean "安全文件传输工具.spec"

echo 检查是否打包成功...
if exist "dist\安全文件传输工具.exe" (
    echo.
    echo 打包成功！
    echo 可执行文件位于: "dist\安全文件传输工具.exe"
    echo (如果你在 .spec 文件中配置的是文件夹模式，则在 dist 内对应的文件夹中)
    echo.
    
    rem 创建简单的运行说明
    echo 创建运行说明到 "dist\运行说明.txt"...
    (
        echo === 安全文件传输工具运行说明 ===
        echo.
        echo 1. 本程序是单文件可执行程序 (如果使用 --onefile 打包)。
        echo 2. 如果程序在其他Windows电脑上无法运行，特别是提示缺少DLL（如VCRUNTIME140.dll等）：
        echo    请先尝试安装 Microsoft Visual C++ Redistributable for Visual Studio。
        echo    (请根据你打包时使用的Python位数选择下载：x86对应32位，x64对应64位)
        echo    官方链接: https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
        echo.
        echo 3. 程序需要网络访问权限。如果你的防火墙弹出提示，请允许其访问网络。
        echo 4. 发送方和接收方都需要运行此程序。
        echo 5. 服务器端(发送方)的IP地址设置：
        echo    - 程序会尝试自动检测一个IP地址作为建议。
        echo    - 推荐在服务器的IP地址栏输入 "0.0.0.0"，这样可以监听所有网络接口。
        echo    - 如果使用特定IP，请确保该IP是局域网内其他计算机可以访问到的IP。
        echo.
        echo === 说明结束 ===
    ) > "dist\运行说明.txt"
    echo.
    echo 运行说明已创建。
    echo.
) else (
    echo.
    echo 打包失败，请检查上面的 PyInstaller 日志输出。
    echo.
)

echo 打包过程完成！
pause