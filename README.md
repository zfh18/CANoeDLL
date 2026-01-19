# CANoeDLL 使用说明

本工程用于在 Cursor 中通过 CMake 生成 CANoe 使用的 CAPL DLL。

## 目录结构

以下目录必须保留在 `CANoeDLL` 根目录：

- `Sources/`：DLL 源码与导出定义文件（主文件 `cryptodll.cpp`）
- `Includes/`：CANoe 接口头文件
- `ExtInclude/`：Crypto++ 头文件
- `ExtLib/`：Crypto++ 静态库（`cryptlib32.lib` / `cryptlib64.lib`）

## 依赖

- Visual Studio（已安装 C++ 工具集）
- CMake Tools 扩展（Cursor 内已安装）

## 构建方式（Cursor）

> 当前状态栏不显示 Configure Preset，请使用命令面板切换配置。

1. 命令面板 `CMake: Select Configure Preset`：
   - `x86 (Win32)` 或 `x64`
2. 命令面板 `CMake: Configure`
3. 命令面板 `CMake: Set Build Target`：
   - `cryptodll` 或 `parseflashfile`
4. 命令面板 `CMake: Select Build Preset`：
   - `Release | x86 (Win32)` 或 `Release | x64`
5. 命令面板 `CMake: Build`

> 构建时会生成 `.map` 文件，便于查看链接内容。

## 输出文件

- `cryptodll`：
  - x86：`build/x86/bin/Release/cryptodll.dll`
  - x64：`build/x64/bin/Release/cryptodll.dll`
- `parseflashfile`：
  - x86：`build/x86/bin/Release/parseflashfile.dll`
  - x64：`build/x64/bin/Release/parseflashfile.dll`
- 自测程序：
  - x86：`build/x86/bin/Release/cryptodll_selftest.exe`
  - x64：`build/x64/bin/Release/cryptodll_selftest.exe`
- Map 文件：
  - x86：`build/x86/bin/Release/cryptodll.map`
  - x64：`build/x64/bin/Release/cryptodll.map`
  - x86：`build/x86/bin/Release/parseflashfile.map`
  - x64：`build/x64/bin/Release/parseflashfile.map`

## 导出函数（节选）

- `dllRSASignMessagePSS` / `dllRSASignByteArrayPSS`：RSA PSS 签名
- `dllRSASignMessagePKCS1` / `dllRSASignByteArrayPKCS1`：RSA PKCS#1 v1.5 签名
- `dllHash256`：SHA-256 哈希
- `dllCRC32`：CRC32 校验
- `dllCRC32Custom`：CRC32（可配置多项式/初始值/异或值/输入输出反转）
- `dllCMACAES`：CMAC-AES（支持 128/192/256 位密钥）
- `dllGenerateX509Certificate`：CA 签名 X.509 证书（DER，RSA 任意位数）
- `dllGenerateX509CertificateWithPublicKey`：CA 签名 X.509 证书（DER，输入为公钥）
- `dllExtractPublicKeyParams`：提取 RSA 公钥参数
- `dllparseFile`：解析 HEX/S19/BIN 文件（返回类型）
- `dllgetBlockCount` / `dllgetBlockStartAddress` / `dllgetBlockDataLength` / `dllgetBlockData`：获取解析后的数据块信息
- `dllgetLastErrorMessage`：获取上一次解析错误信息（参数为 `message_out` 和 `maxLength`）

## 常见问题

### 1) LNK2038：_ITERATOR_DEBUG_LEVEL / RuntimeLibrary 不匹配

原因：工程配置为 Release，但引用的 `cryptlib32.lib` 是 Debug 版（`MTd`）。

解决：
- 使用 Release 版 `cryptlib32.lib`（必须与当前配置匹配）
- 或者改用 Debug 配置（不推荐用于发布）

### 2) x64 链接报 _VIARegisterCDLL@4 找不到

x64 不使用 stdcall 修饰名，需要使用 `capldll_x64.def`。

本工程已在 CMake 中自动根据 32/64 位选择 `.def` 文件。

### 3) Build 时无法选择 32/64 位

Build 只会使用当前 **Configure Preset**。  
请先切换 **Configure Preset** 再 Build。

