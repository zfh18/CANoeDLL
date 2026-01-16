# CANoeDLL 使用说明

本工程用于在 Cursor 中通过 CMake 生成 CANoe 使用的 CAPL DLL。

## 目录结构

以下目录必须保留在 `CANoeDLL` 根目录：

- `Sources/`：DLL 源码与导出定义文件
- `Includes/`：CANoe 接口头文件
- `ExtInclude/`：Crypto++ 头文件
- `ExtLib/`：Crypto++ 静态库（`cryptlib32.lib` / `cryptlib64.lib`）

## 依赖

- Visual Studio（已安装 C++ 工具集）
- CMake Tools 扩展（Cursor 内已安装）

## 构建方式（Cursor）

1. 状态栏选择 **Configure Preset**：
   - `x86 (Win32)` 或 `x64`
2. 状态栏选择 **Build Preset**：
   - `Release | x86 (Win32)` 或 `Release | x64`
3. 点击 **Build**

> 构建时会生成 `.map` 文件，便于查看链接内容。

## 输出文件

- x86：`build/x86/bin/Release/capldll.dll`
- x64：`build/x64/bin/Release/capldll.dll`
- Map 文件：
  - x86：`build/x86/bin/Release/capldll.map`
  - x64：`build/x64/bin/Release/capldll.map`

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

