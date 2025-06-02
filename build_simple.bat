@echo off
chcp 65001 >nul
echo 开始打包安全文件传输工具...

rem --- 安装依赖 ---
echo 正在安装/更新依赖...
pip install -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple -r requirements.txt
if errorlevel 1 (
    echo 错误：依赖安装失败。
    pause
    exit /b 1
)

echo 开始使用 PyInstaller 打包...
pyinstaller --noconfirm --clean "安全文件传输工具.spec"

echo 检查是否打包成功...
if exist "dist\安全文件传输工具.exe" (
    echo.
    echo 打包成功！
    echo 可执行文件位于: "dist\安全文件传输工具.exe"
    echo.
    
    rem 创建运行说明
    echo 创建运行说明到 "dist\运行说明.txt"...
    (
        echo === 安全文件传输工具运行说明 ===
        echo.
        echo 1. 本程序是单文件可执行程序。
        echo 2. 如果程序在其他Windows电脑上无法运行，特别是提示缺少DLL：
        echo    请安装 Microsoft Visual C++ Redistributable for Visual Studio 2015-2022。
        echo    下载地址: https://aka.ms/vs/17/release/vc_redist.x64.exe
        echo.
        echo 3. 程序需要网络访问权限。如果防火墙弹出提示，请允许其访问网络。
        echo 4. 发送方和接收方都需要运行此程序。
        echo 5. 程序会自动发现局域网内的其他节点。
        echo 6. 首次连接时会进行信任验证，请仔细核对公钥指纹。
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