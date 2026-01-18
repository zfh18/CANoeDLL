/*----------------------------------------------------------------------------
|
| File Name: parseflashfile.cpp
|
|            Example of a capl DLL implementation module and using CAPLLbacks.
|-----------------------------------------------------------------------------
|               A U T H O R   I D E N T I T Y
|-----------------------------------------------------------------------------
|   Author             Initials
|   ------             --------
|   Thomas  Riegraf    Ri              Vector Informatik GmbH
|   Hans    Quecke     Qu              Vector Informatik GmbH
|   Stefan  Albus      As              Vector Informatik GmbH
|-----------------------------------------------------------------------------
|               R E V I S I O N   H I S T O R Y
|-----------------------------------------------------------------------------
| Date         Ver  Author  Description
| ----------   ---  ------  --------------------------------------------------
| 2003-10-07   1.0  As      Created
| 2007-03-26   1.1  Ej      Export of the DLL function table as variable
|                           Use of CAPL_DLL_INFO3
|                           Support of long name CAPL function calls
| 2020-01-23   1.2  As      Support for GCC and Clang compiler on Linux
|                           Support for MINGW-64 compiler on Windows
|-----------------------------------------------------------------------------
|               C O P Y R I G H T
|-----------------------------------------------------------------------------
| Copyright (c) 1994 - 2003 by Vector Informatik GmbH.  All rights reserved.
 ----------------------------------------------------------------------------*/
#include "capl_common.h"

#include <string.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

/*
 * HEX/S19/BIN 文件解析器
 * 支持解析 Intel HEX、Motorola S-record 和二进制文件格式
 * 解析结果存储在全局变量中，可通过接口函数获取
 */

 // ----------------------- 以下为新增加函数 ------------------------- //
// 文件类型枚举
enum FileType {
     FILE_TYPE_INVALID = 0,
     FILE_TYPE_HEX,
     FILE_TYPE_S19,
     FILE_TYPE_BIN
};

// 数据块结构
struct DataBlock {
     uint32_t startAddress;      // 起始地址
     uint32_t dataLength;        // 实际数据长度
     std::vector<uint8_t> data;  // 数据内容
};

// 解析结果结构
struct ParseResult {
     FileType fileType;              // 文件类型
     bool success;                   // 解析是否成功
     std::string errorMessage;       // 错误信息
     std::vector<DataBlock> blocks;  // 数据块列表
};

// 最后一次解析的结果（静态变量）
static ParseResult g_lastParseResult;

// 将十六进制字符转换为数值
static uint8_t hexCharToValue(char c) {
     if (c >= '0' && c <= '9') return c - '0';
     if (c >= 'A' && c <= 'F') return c - 'A' + 10;
     if (c >= 'a' && c <= 'f') return c - 'a' + 10;
     return 0;
}

// 将两个十六进制字符转换为一个字节
static uint8_t hexToByte(const char* hex) {
     return (hexCharToValue(hex[0]) << 4) | hexCharToValue(hex[1]);
}

// 移除字符串末尾的回车符（如果存在）
static void removeCarriageReturn(std::string& line) {
     if (!line.empty() && line.back() == '\r') {
         line.pop_back();
     }
}

// 计算HEX文件校验和（累加和取反加1，即二进制补码）
static uint8_t calculateHexChecksum(const uint8_t* data, size_t length) {
     uint8_t sum = 0;
     for (size_t i = 0; i < length; i++) {
         sum += data[i];
     }
     return (~sum) + 1;  // 二进制补码
}

// 计算S19文件校验和（累加和的低8位取一补码：0xFF - sum）
static uint8_t calculateS19Checksum(const uint8_t* data, size_t length) {
     uint8_t sum = 0;
     for (size_t i = 0; i < length; i++) {
         sum += data[i];
     }
     return 0xFF - sum;  // 一补码（one's complement）
}

// 验证HEX文件行格式
static bool validateHexLine(const std::string& line) {
     if (line.empty() || line[0] != ':') {
         return false;
     }
     if (line.length() < 11) {  // 最小长度：:LLAAAATTCC (11字符)
         return false;
     }
     if ((line.length() - 1) % 2 != 0) {  // 除冒号外，其他字符必须是偶数
         return false;
     }
 
     // 验证所有字符都是十六进制
     for (size_t i = 1; i < line.length(); i++) {
         if (!isxdigit(static_cast<unsigned char>(line[i]))) {
             return false;
         }
     }
 
     return true;
 }
 
 // 解析HEX文件（Intel HEX格式）
 // 格式：:LLAAAATTDD...DDCC
 // LL=长度, AAAA=地址, TT=类型, DD=数据, CC=校验和
 static ParseResult parseHexFile(const std::string& filename) {
     ParseResult result;
     result.fileType = FILE_TYPE_HEX;
     result.success = false;
 
     std::ifstream file(filename, std::ios::binary);
     if (!file.is_open()) {
         result.errorMessage = "无法打开文件: " + filename;
         return result;
     }
 
     std::string line;
     uint32_t extendedAddress = 0;  // 扩展地址（用于0x02和0x04记录）
     bool endRecordFound = false;   // 是否找到结束记录
 
     while (std::getline(file, line)) {
         // 跳过空行（在移除回车符之前检查，提高效率）
         if (line.empty()) {
             continue;
         }
 
         // 移除回车符
         removeCarriageReturn(line);
         if (line.empty()) {
             continue;
         }
 
         // 验证行格式
         if (!validateHexLine(line)) {
             result.errorMessage = "无效的HEX行格式: " + line;
             return result;
         }
 
         // 解析记录
         size_t pos = 1;  // 跳过冒号
 
         uint8_t recordLength = hexToByte(&line[pos]);
         pos += 2;
 
         // 验证记录长度（HEX格式最大255字节）
         if (recordLength > 255) {
             result.errorMessage = "HEX记录长度无效: " + line;
             return result;
         }
 
         // 检查行长度是否足够包含所有数据
         // 格式：: + LL(2) + AAAA(4) + TT(2) + DD...(recordLength*2) + CC(2)
         constexpr size_t HEX_MIN_FIELDS = 1 + 2 + 4 + 2 + 2;  // : + LL + AAAA + TT + CC
         size_t expectedLength = HEX_MIN_FIELDS + recordLength * 2;
         if (line.length() < expectedLength) {
             result.errorMessage = "HEX行长度不匹配: " + line;
             return result;
         }
 
         uint16_t address = (hexToByte(&line[pos]) << 8) | hexToByte(&line[pos + 2]);
         pos += 4;
 
         uint8_t recordType = hexToByte(&line[pos]);
         pos += 2;
 
         // 读取数据
         std::vector<uint8_t> recordData;
         recordData.reserve(recordLength);  // 预分配内存
         for (uint8_t i = 0; i < recordLength; i++) {
             recordData.push_back(hexToByte(&line[pos]));
             pos += 2;
         }
 
         // 读取并验证校验和
         uint8_t checksum = hexToByte(&line[pos]);
         // 直接计算校验和，避免创建临时vector
         uint8_t checksumBytes[4 + 255];  // 最大支持255字节数据
         checksumBytes[0] = recordLength;
         checksumBytes[1] = (address >> 8) & 0xFF;
         checksumBytes[2] = address & 0xFF;
         checksumBytes[3] = recordType;
         for (uint8_t i = 0; i < recordLength; i++) {
             checksumBytes[4 + i] = recordData[i];
         }
 
         uint8_t calculatedChecksum = calculateHexChecksum(checksumBytes, 4 + recordLength);
         if (calculatedChecksum != checksum) {
             result.errorMessage = "校验和错误: " + line;
             return result;
         }
 
         // 处理不同类型的记录
         switch (recordType) {
         case 0x00: {  // 数据记录
             uint32_t fullAddress = extendedAddress + address;  // 完整地址 = 扩展地址 + 段地址
 
             // 检查是否需要创建新块或合并到现有块
             // 如果地址连续，则合并到现有块；否则创建新块
             if (result.blocks.empty() ||
                 result.blocks.back().startAddress + result.blocks.back().dataLength != fullAddress) {
                 // 创建新块
                 DataBlock block;
                 block.startAddress = fullAddress;
                 block.dataLength = recordLength;
                 block.data = recordData;
                 result.blocks.push_back(block);
             }
             else {
                 // 合并到最后一个块（地址连续）
                 result.blocks.back().dataLength += recordLength;
                 size_t oldSize = result.blocks.back().data.size();
                 result.blocks.back().data.resize(oldSize + recordLength);
                 std::copy(recordData.begin(), recordData.end(),
                     result.blocks.back().data.begin() + oldSize);
             }
             break;
         }
         case 0x02: {  // 扩展段地址记录（用于16位段地址）
             if (recordLength != 2) {
                 result.errorMessage = "扩展段地址记录长度错误: " + line;
                 return result;
             }
             // 段地址左移4位后与段内地址相加
             extendedAddress = ((uint32_t)recordData[0] << 8 | recordData[1]) << 4;
             break;
         }
         case 0x04: {  // 扩展线性地址记录（用于32位线性地址）
             if (recordLength != 2) {
                 result.errorMessage = "扩展线性地址记录长度错误: " + line;
                 return result;
             }
             // 线性地址左移16位后与段内地址相加
             extendedAddress = ((uint32_t)recordData[0] << 8 | recordData[1]) << 16;
             break;
         }
         case 0x01: {  // 结束记录（文件结束标记）
             endRecordFound = true;
             break;
         }
         default:
             break;
         }
     }
 
     if (!endRecordFound && result.blocks.empty()) {
         result.errorMessage = "未找到有效数据或结束记录";
         return result;
     }
 
     result.success = true;
     return result;
 }
 
 // 验证S19文件行格式
static bool validateS19Line(const std::string& line) {
     if (line.empty() || line[0] != 'S') {
         return false;
     }
     if (line.length() < 4) {  // 最小长度：S0LL (4字符)
         return false;
     }
     if (!isdigit(static_cast<unsigned char>(line[1]))) {
         return false;
     }
 
     // 验证所有字符都是十六进制（除了开头的S和记录类型）
     for (size_t i = 2; i < line.length(); i++) {
         if (!isxdigit(static_cast<unsigned char>(line[i]))) {
             return false;
         }
     }
 
     return true;
 }
 
 // 解析S19文件（Motorola S-record格式）
 // 格式：STLLAAAADD...DDCC
 // S=起始符, T=类型, LL=长度, AAAA=地址, DD=数据, CC=校验和
 // S0=头记录, S1/S2/S3=数据记录, S7/S8/S9=结束记录
static ParseResult parseS19File(const std::string& filename) {
     ParseResult result;
     result.fileType = FILE_TYPE_S19;
     result.success = false;
 
     std::ifstream file(filename, std::ios::binary);
     if (!file.is_open()) {
         result.errorMessage = "无法打开文件: " + filename;
         return result;
     }
 
     std::string line;
     bool endRecordFound = false;  // 是否找到结束记录
 
     while (std::getline(file, line)) {
         // 跳过空行（在移除回车符之前检查，提高效率）
         if (line.empty()) {
             continue;
         }
 
         // 移除回车符
         removeCarriageReturn(line);
         if (line.empty()) {
             continue;
         }
 
         // 验证行格式
         if (!validateS19Line(line)) {
             result.errorMessage = "无效的S19行格式: " + line;
             return result;
         }
 
         // 解析记录类型
         uint8_t recordType = line[1] - '0';
 
         // 读取记录长度
         uint8_t recordLength = hexToByte(&line[2]);
 
         // 验证记录长度（S19格式最大255字节）
         if (recordLength == 0 || recordLength > 255) {
             result.errorMessage = "S19记录长度无效: " + line;
             return result;
         }
 
         // 验证记录长度
         // 格式：S(1) + 类型(1) + 长度(2) + 地址+数据+校验和
         // 记录长度字段包含：长度字节(1) + 地址字节 + 数据字节 + 校验和字节(1)
         // 所以总字符数 = 2 + 2 + (recordLength - 1) * 2
         constexpr size_t S19_MIN_FIELDS = 2 + 2;  // S + 类型 + 长度(2字符)
         size_t expectedLength = S19_MIN_FIELDS + (recordLength - 1) * 2;
         if (line.length() < expectedLength) {
             result.errorMessage = "S19记录长度不匹配: " + line;
             return result;
         }
 
         size_t pos = 4;  // 跳过 "S" + 类型 + 长度
 
         // 读取地址（根据记录类型确定地址长度）
         uint32_t address = 0;
         uint8_t addressBytes = 0;
         uint8_t dataBytes = 0;
 
         // 根据记录类型确定地址长度和数据长度
         switch (recordType) {
         case 0:  // S0 - 头记录（包含描述信息）
             addressBytes = 2;  // 16位地址
             dataBytes = recordLength - addressBytes - 1;  // 长度 = 总长度 - 地址字节 - 校验和
             break;
         case 9:  // S9 - 结束记录（16位地址）
             addressBytes = 2;
             break;
         case 1:  // S1 - 数据记录（16位地址）
             addressBytes = 2;
             dataBytes = recordLength - addressBytes - 1;
             break;
         case 2:  // S2 - 数据记录（24位地址）
         case 8:  // S8 - 结束记录（24位地址）
             addressBytes = 3;
             if (recordType == 2) {
                 dataBytes = recordLength - addressBytes - 1;
             }
             break;
         case 3:  // S3 - 数据记录（32位地址）
         case 7:  // S7 - 结束记录（32位地址）
             addressBytes = 4;
             if (recordType == 3) {
                 dataBytes = recordLength - addressBytes - 1;
             }
             break;
         default:
             result.errorMessage = "未知的S19记录类型: " + line;
             return result;
         }
 
         // 读取地址
         for (uint8_t i = 0; i < addressBytes; i++) {
             address = (address << 8) | hexToByte(&line[pos]);
             pos += 2;
         }
 
         // 读取数据（仅数据记录）
         std::vector<uint8_t> recordData;
         if (dataBytes > 0) {
             recordData.reserve(dataBytes);  // 预分配内存
             for (uint8_t i = 0; i < dataBytes; i++) {
                 recordData.push_back(hexToByte(&line[pos]));
                 pos += 2;
             }
         }
 
         // 读取并验证校验和
         uint8_t checksum = hexToByte(&line[pos]);
 
         // 直接计算校验和，避免创建临时vector
         uint8_t checksumBytes[1 + 4 + 255];  // 最大支持255字节数据
         size_t checksumLen = 0;
         checksumBytes[checksumLen++] = recordLength;
         for (uint8_t i = 0; i < addressBytes; i++) {
             checksumBytes[checksumLen++] = (address >> (8 * (addressBytes - 1 - i))) & 0xFF;
         }
         for (uint8_t i = 0; i < dataBytes; i++) {
             checksumBytes[checksumLen++] = recordData[i];
         }
 
         uint8_t calculatedChecksum = calculateS19Checksum(checksumBytes, checksumLen);
         if (calculatedChecksum != checksum) {
             result.errorMessage = "校验和错误: " + line;
             return result;
         }
 
         // 处理不同类型的记录
         switch (recordType) {
         case 0:  // S0 - 头记录（包含文件描述信息，通常忽略）
             break;
         case 1:  // S1 - 数据记录（16位地址）
         case 2:  // S2 - 数据记录（24位地址）
         case 3: {  // S3 - 数据记录（32位地址）
             // 检查是否需要创建新块或合并到现有块
             // 如果地址连续，则合并到现有块；否则创建新块
             if (result.blocks.empty() ||
                 result.blocks.back().startAddress + result.blocks.back().dataLength != address) {
                 // 创建新块
                 DataBlock block;
                 block.startAddress = address;
                 block.dataLength = dataBytes;
                 block.data = recordData;
                 result.blocks.push_back(block);
             }
             else {
                 // 合并到最后一个块（地址连续）
                 result.blocks.back().dataLength += dataBytes;
                 size_t oldSize = result.blocks.back().data.size();
                 result.blocks.back().data.resize(oldSize + dataBytes);
                 std::copy(recordData.begin(), recordData.end(),
                     result.blocks.back().data.begin() + oldSize);
             }
             break;
         }
         case 7:  // S7 - 结束记录（32位地址，包含执行地址）
         case 8:  // S8 - 结束记录（24位地址，包含执行地址）
         case 9:  // S9 - 结束记录（16位地址，包含执行地址）
             endRecordFound = true;
             break;
         }
     }
 
     if (!endRecordFound && result.blocks.empty()) {
         result.errorMessage = "未找到有效数据或结束记录";
         return result;
     }
 
     result.success = true;
     return result;
 }
 
 // 解析BIN文件（纯二进制文件）
 // BIN文件没有格式信息，直接读取所有字节作为一个数据块
 // 参数：
 //   filename - 文件路径
 //   startAddress - 数据块的起始地址（BIN文件本身不包含地址信息，需要手动指定）
 //                  例如：如果BIN文件要加载到0x1000地址，则传入0x1000
static ParseResult parseBinFile(const std::string& filename, uint32_t startAddress = 0) {
     ParseResult result;
     result.fileType = FILE_TYPE_BIN;
     result.success = false;
 
     // 以二进制模式打开，并定位到文件末尾以获取文件大小
     std::ifstream file(filename, std::ios::binary | std::ios::ate);
     if (!file.is_open()) {
         result.errorMessage = "无法打开文件: " + filename;
         return result;
     }
 
     std::streamsize fileSize = file.tellg();  // 获取文件大小
     file.seekg(0, std::ios::beg);  // 回到文件开头
 
     if (fileSize <= 0) {
         result.errorMessage = "BIN文件为空";
         return result;
     }
 
     // 检查文件大小是否合理（避免过大文件导致内存问题）
     constexpr std::streamsize MAX_FILE_SIZE = 1024ULL * 1024 * 1024;  // 1GB
     if (fileSize > MAX_FILE_SIZE) {
         result.errorMessage = "BIN文件过大（超过1GB）";
         return result;
     }
 
     // 创建单个数据块
     DataBlock block;
     block.startAddress = startAddress;
     block.dataLength = static_cast<uint32_t>(fileSize);
     block.data.resize(block.dataLength);
 
     if (!file.read(reinterpret_cast<char*>(block.data.data()), fileSize)) {
         result.errorMessage = "读取BIN文件失败";
         return result;
     }
 
     // 验证实际读取的字节数
     std::streamsize bytesRead = file.gcount();
     if (bytesRead != fileSize) {
         result.errorMessage = "BIN文件读取不完整";
         return result;
     }
 
     result.blocks.push_back(block);
     result.success = true;
     return result;
 }
 
 // 自动识别文件类型并解析
 // 参数：
 //   filename - 要解析的文件路径
 //   binStartAddress - BIN文件的起始地址（仅对BIN文件有效，HEX和S19文件忽略此参数）
 //                     因为BIN文件是纯二进制数据，没有地址信息，需要手动指定起始地址
 //                     默认值为0
 // 返回值：成功返回文件类型，失败返回 FILE_TYPE_INVALID
 // 解析结果存储在全局变量中，可通过 getBlockCount() 等函数获取
FileType CAPLEXPORT CAPLPASCAL parseFile(const char* filename, uint32_t binStartAddress = 0) {
     // 初始化结果
     g_lastParseResult.fileType = FILE_TYPE_INVALID;
     g_lastParseResult.success = false;
     g_lastParseResult.blocks.clear();
 
     if (filename == nullptr) {
         g_lastParseResult.errorMessage = "文件名不能为空";
         return FILE_TYPE_INVALID;
     }
 
     // 读取第一行以判断文件类型
     std::ifstream file(filename);
     if (!file.is_open()) {
         g_lastParseResult.errorMessage = std::string("无法打开文件: ") + filename;
         return FILE_TYPE_INVALID;
     }
 
     std::string firstLine;
     std::getline(file, firstLine);
     file.close();
 
     // 移除回车符（如果存在）
     removeCarriageReturn(firstLine);
 
     ParseResult result;
     // 根据第一行首字符判断文件类型
     if (!firstLine.empty() && firstLine[0] == ':') {
         // HEX文件：以冒号开头
         result = parseHexFile(std::string(filename));
     }
     else if (!firstLine.empty() && firstLine[0] == 'S' && isdigit(static_cast<unsigned char>(firstLine[1]))) {
         // S19文件：以S开头，第二个字符是数字
         result = parseS19File(std::string(filename));
     }
     else {
         // 其他情况：尝试作为BIN文件解析
         result = parseBinFile(std::string(filename), binStartAddress);
     }
 
     // 保存结果到全局变量（使用move语义减少拷贝）
     g_lastParseResult = std::move(result);
 
     // 返回文件类型，失败返回 FILE_TYPE_INVALID
     return g_lastParseResult.success ? g_lastParseResult.fileType : FILE_TYPE_INVALID;
 }
 
 // 获取数据块数量
size_t CAPLEXPORT CAPLPASCAL getBlockCount() {
     if (!g_lastParseResult.success) {
         return 0;
     }
     return g_lastParseResult.blocks.size();
 }
 
 // 获取指定数据块的起始地址
uint32_t CAPLEXPORT CAPLPASCAL getBlockStartAddress(size_t blockIndex) {
     if (!g_lastParseResult.success || blockIndex >= g_lastParseResult.blocks.size()) {
         return 0;
     }
     return g_lastParseResult.blocks[blockIndex].startAddress;
 }
 
 // 获取指定数据块的数据长度
uint32_t CAPLEXPORT CAPLPASCAL getBlockDataLength(size_t blockIndex) {
     if (!g_lastParseResult.success || blockIndex >= g_lastParseResult.blocks.size()) {
         return 0;
     }
     return g_lastParseResult.blocks[blockIndex].dataLength;
 }
 
 // 获取指定数据块的数据（通过数组参数返回）
 // 参数：
 //   blockIndex - 数据块索引
 //   data - 输出参数，用于接收数据的数组指针（必须预先分配足够空间）
 //   maxLength - 数组的最大长度
 // 返回值：实际复制的字节数，失败返回0
size_t CAPLEXPORT CAPLPASCAL getBlockData(size_t blockIndex, uint8_t* data, size_t maxLength) {
     if (!g_lastParseResult.success || blockIndex >= g_lastParseResult.blocks.size() || data == nullptr || maxLength == 0) {
         return 0;
     }
     const auto& block = g_lastParseResult.blocks[blockIndex];
     // 确保数据长度一致性
     size_t actualDataSize = (static_cast<size_t>(block.dataLength) < block.data.size())
         ? static_cast<size_t>(block.dataLength)
         : block.data.size();
     size_t copyLength = (actualDataSize < maxLength) ? actualDataSize : maxLength;
     std::copy(block.data.begin(), block.data.begin() + copyLength, data);
     return copyLength;
 }
// 获取错误信息
// 返回值：实际写入的字符数（不含结尾的 '\0'）
uint32_t CAPLEXPORT CAPLPASCAL getLastErrorMessage(char* message_out, uint32_t maxLength) {
    if (message_out == nullptr || maxLength == 0) {
        return 0;
    }

    const std::string& msg = g_lastParseResult.errorMessage;
    uint32_t copyLen = static_cast<uint32_t>(msg.size());
    if (copyLen >= maxLength) {
        copyLen = maxLength - 1;
    }

    if (copyLen > 0) {
        memcpy(message_out, msg.data(), copyLen);
    }
    message_out[copyLen] = '\0';
    return copyLen;
}
 
 // ============================================================================
 // CAPL_DLL_INFO_LIST : list of exported functions
 //   The first field is predefined and mustn't be changed!
 //   The list has to end with a {0,0} entry!
 // New struct supporting function names with up to 50 characters
 // ============================================================================
CAPL_DLL_INFO4 table[] = {
 {CDLL_VERSION_NAME, (CAPL_FARCALL)CDLL_VERSION, "", "", CAPL_DLL_CDECL, 0xabcd, CDLL_EXPORT },
 
   {"dllparseFile", (CAPL_FARCALL)parseFile, "Parse Flash File", "解析 hex s19 bin 文件，返回文件类型：Invalid(0) Hex(1) S19(2) Bin(3)", 'D', 2, {'C','D'}, "\001\000", {"filename","binStartAddress"}},
   {"dllgetBlockCount", (CAPL_FARCALL)getBlockCount, "Parse Flash File", "获取解析文件后得到的数据块数量", 'D', 0, {}, "", {}},
   {"dllgetBlockStartAddress", (CAPL_FARCALL)getBlockStartAddress, "Parse Flash File", "获取对应索引的数据块起始地址", 'D', 1, {'D'}, "\000", {"blockIndex"}},
   {"dllgetBlockDataLength", (CAPL_FARCALL)getBlockDataLength, "Parse Flash File", "获取对应索引的数据块数据长度", 'D', 1, {'D'}, "\000", {"blockIndex"}},
   {"dllgetBlockData", (CAPL_FARCALL)getBlockData, "Parse Flash File", "获取对应索引的数据块数据，返回实际取得的数据长度", 'D', 3, {'D', 'B', 'D'}, "\000\001\000", {"blockIndex","data","maxLength"}},
  {"dllgetLastErrorMessage", (CAPL_FARCALL)getLastErrorMessage, "Parse Flash File", "获取上一次解析错误信息", 'D', 2, {'C','D'}, "\001\000", {"message_out","maxLength"}},
   {0, 0}
 };
 CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = table;
