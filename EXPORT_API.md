# CAPL DLL Export API

本文档汇总 `Sources/cryptodll.cpp` 与 `Sources/parseflashfile.cpp` 中的导出函数，按模块分类说明参数与返回值，供 CAPL 调用时查阅。

## 约定

- 返回值为 `0` 通常表示失败；非 0 表示成功（具体见每个函数说明）
- 缓冲区参数由调用方分配，长度不足会返回失败
- `byte[]` 表示 CAPL 字节数组（对应 C/C++ 的 `unsigned char*`）

## cryptodll.cpp

### Algorithm 分类

#### `dllHash256(message, messageLen, hash_out, hash_out_len)`
- 功能：计算 SHA-256
- 参数：
  - `message`：输入字节数组
  - `messageLen`：输入长度
  - `hash_out`：输出缓冲区
  - `hash_out_len`：输出缓冲区长度
- 返回：成功返回 `32`，失败返回 `0`

#### `dllCRC32(message, messageLen, crc_out, crc_out_len)`
- 功能：计算 CRC32（输出 4 字节）
- 返回：成功返回 `4`，失败返回 `0`

#### `dllCRC8J1850(message, messageLen)`
- 功能：计算 CRC-8/SAE-J1850
- 算法参数：`poly=0x1D, init=0xFF, refin=false, refout=false, xorout=0xFF`
- 返回：成功返回 CRC8 值（`0~255`），失败返回 `-1`
- 测试向量：输入 `3C 00 B0 00 03` 时输出 `0x32`

#### `dllCRC8Custom(message, messageLen, poly, initValue, xorOut, refin, refout)`
- 功能：按可配置参数计算 CRC8
- 参数：
  - `poly`：多项式（非反射形式，取值 `0x00~0xFF`）
  - `initValue`：初值（取值 `0x00~0xFF`）
  - `xorOut`：输出异或值（取值 `0x00~0xFF`）
  - `refin`：输入是否反转（0/非0）
  - `refout`：输出是否反转（0/非0）
- 返回：成功返回 CRC8 值（`0~255`），失败返回 `-1`
- 示例：使用 `poly=0x1D, initValue=0xFF, xorOut=0xFF, refin=0, refout=0` 时等价于 `dllCRC8J1850`

#### `dllCRC32Custom(message, messageLen, poly, initValue, xorOut, refin, refout, crc_out, crc_out_len)`
- 功能：按可配置参数计算 CRC32
- 参数：
  - `poly`：多项式（非反射形式）
  - `initValue`：初值
  - `xorOut`：输出异或值
  - `refin`：输入是否反转（0/非0）
  - `refout`：输出是否反转（0/非0）
- 返回：成功返回 `4`，失败返回 `0`

#### `dllCMACAES(key, keyLen, message, messageLen, mac_out, mac_out_len)`
- 功能：计算 CMAC-AES
- 说明：支持密钥长度 `16/24/32` 字节
- 返回：成功返回 `16`，失败返回 `0`

#### `dllHMACSHA1(key, keyLen, message, messageLen, mac_out, mac_out_len)`
- 功能：计算 HMAC-SHA1
- 返回：成功返回 `20`，失败返回 `0`

### RSA 分类

#### `dllRSASignMessagePSS(privateKeyHex, message, signature_out, signature_out_capacity)`
- 功能：对字符串做 RSA PSS 签名（SHA-256）
- 说明：`signature_out_capacity` 是调用方提供的输出缓冲区容量
- 返回：成功返回签名字节数，失败返回 `0`

#### `dllRSASignMessagePKCS1(privateKeyHex, message, signature_out, signature_out_capacity)`
- 功能：对字符串做 RSA PKCS#1 v1.5 签名（SHA-256）
- 说明：`signature_out_capacity` 是调用方提供的输出缓冲区容量
- 返回：成功返回签名字节数，失败返回 `0`

#### `dllRSASignByteArrayPSS(privateKeyHex, message, messageLen, signature_out, signature_out_capacity)`
- 功能：对字节数组做 RSA PSS 签名（SHA-256）
- 说明：`signature_out_capacity` 是调用方提供的输出缓冲区容量
- 返回：成功返回签名字节数，失败返回 `0`

#### `dllRSASignByteArrayPKCS1(privateKeyHex, message, messageLen, signature_out, signature_out_capacity)`
- 功能：对字节数组做 RSA PKCS#1 v1.5 签名（SHA-256）
- 说明：`signature_out_capacity` 是调用方提供的输出缓冲区容量
- 返回：成功返回签名字节数，失败返回 `0`

#### `dllGenerateX509Certificate(caPrivateKeyHex, caCN, subjectPrivateKeyHex, subjectCN, daysValid, cert_out, cert_out_len)`
- 功能：生成 CA 签名 X.509 证书（DER，输入为被签发者私钥）
- 返回：成功返回证书长度，失败返回 `0`

#### `dllGenerateX509CertificateWithPublicKey(caPrivateKeyHex, caCN, subjectPublicKeyHex, subjectCN, daysValid, cert_out, cert_out_len)`
- 功能：生成 CA 签名 X.509 证书（DER，输入为被签发者公钥）
- 返回：成功返回证书长度，失败返回 `0`

#### `dllExtractPublicKeyParams(keyHex, modulusBytes, modulusLength, publicExponentBytes, publicExponentLength)`
- 功能：从 RSA 私钥或公钥提取公钥参数（n/e）
- 返回：成功返回 `1`，失败返回 `0`
- 说明：`modulusLength`、`publicExponentLength` 返回实际输出长度

## parseflashfile.cpp

### Parse Flash File 分类

#### `dllparseFile(filename, binStartAddress)`
- 功能：解析 `HEX/S19/BIN` 文件并缓存结果
- 参数：
  - `filename`：文件路径
  - `binStartAddress`：BIN 文件起始地址（HEX/S19 可忽略）
- 返回：文件类型枚举
  - `0`：Invalid
  - `1`：Hex
  - `2`：S19
  - `3`：Bin

#### `dllgetBlockCount()`
- 功能：获取上次解析得到的数据块数量
- 返回：数据块数量；解析失败时返回 `0`

#### `dllgetBlockStartAddress(blockIndex)`
- 功能：获取指定数据块起始地址
- 返回：地址；无效索引或失败返回 `0`

#### `dllgetBlockDataLength(blockIndex)`
- 功能：获取指定数据块长度
- 返回：长度；无效索引或失败返回 `0`

#### `dllgetBlockData(blockIndex, data, maxLength)`
- 功能：读取指定数据块内容
- 返回：实际拷贝字节数；失败返回 `0`

#### `dllgetLastErrorMessage(message_out, maxLength)`
- 功能：获取上一次解析失败错误信息
- 返回：写入的字符数（不含结尾 `\0`）；失败返回 `0`

## 调用顺序建议（parseflashfile）

1. 调 `dllparseFile()`
2. 成功后调 `dllgetBlockCount()`
3. 循环调用 `dllgetBlockStartAddress()` + `dllgetBlockDataLength()` + `dllgetBlockData()`
4. 失败时调 `dllgetLastErrorMessage()` 获取原因
