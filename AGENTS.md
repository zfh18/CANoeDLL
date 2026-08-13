# CANoeDLL 项目协作规则

## 语言与注释

- 与用户沟通优先使用中文。
- 每次新增 C/C++ 函数时，必须同步添加简要 Doxygen 风格注释。
- 新增函数注释使用中文，至少包含 `@brief`；对导出函数还应包含必要的 `@param` 和 `@return`。
- 函数之间保留空行，避免新函数与后续函数紧挨在一起。

## 文件编码

- 修改文件前先确认编码，避免破坏已有中文内容。
- `Sources/cryptodll.cpp` 当前不是 UTF-8，按 GBK/ANSI（代码页 936）读取和写入；不要擅自转换成 UTF-8，也不要引入 BOM。
- `README.md` 和 `EXPORT_API.md` 使用 UTF-8 with BOM，修改时保持该编码。
- 对 `Sources/cryptodll.cpp` 做手工编辑时，如果常规补丁工具无法处理编码，应使用编码感知方式修改，并尽量只插入必要内容。

## CAPL DLL 导出

- 新增 CAPL 可调用函数时，函数实现应使用现有导出约定，例如 `CAPLEXPORT CAPLPASCAL`。
- 新增 CAPL 可调用函数后，必须同步更新 `CAPL_DLL_INFO4 table[]` 导出表。
- CAPL 导出名使用 `dll` 前缀，例如 C++ 函数 `CRC8Custom` 对应 CAPL 名 `dllCRC8Custom`。
- 导出表中的返回类型、参数个数、参数类型字符串、数组标记和参数名必须与函数签名保持一致。
- 新增算法接口时，同步更新 `EXPORT_API.md`；用户可见能力变化时，同步更新 `README.md`。

## 算法接口约定

- 算法标准参数、测试向量和 check 值属于接口文档或测试内容，不写入本规则文件。
- 可配置 CRC 函数的 `poly` 参数使用普通非反射形式传入；当 `refin` 非 0 时，函数内部负责反射多项式，并同步在接口文档中说明。

## 构建验证

- 涉及 DLL 导出、函数签名、编译选项或公共接口变更时，需要验证 32 位和 64 位构建。
- GitHub Actions 使用 MSVC 开发者环境加 Ninja preset 构建，避免 CI 依赖固定 Visual Studio generator 版本；本机 `x86`/`x64` preset 可继续用于 VS 2022 方案。
- 本项目可使用 Visual Studio DevCmd 加 VS bundled CMake/Ninja 做干净验证构建。
- 已知工具路径：
  - VS DevCmd: `D:\DevTools\VisualStudio\Community2022\Common7\Tools\VsDevCmd.bat`
  - CMake: `D:\DevTools\VisualStudio\Community2022\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
  - Ninja: `D:\DevTools\VisualStudio\Community2022\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe`
- 推荐验证目录：
  - x86: `build\verify-x86-ninja`
  - x64: `build\verify-x64-ninja`
- 构建后如涉及导出符号，可用 `dumpbin /exports` 检查实际 DLL 导出。
