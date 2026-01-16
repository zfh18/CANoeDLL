/*----------------------------------------------------------------------------
|
| File Name: capldll.cpp
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


#define USECDLL_FEATURE
#define _BUILDNODELAYERDLL

#include "../Includes/cdll.h"
#include "../Includes/VIA.h"
#include "../Includes/VIA_CDLL.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>

#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

#include "rsa.h"
#include "osrng.h"
#include "pssr.h"
#include "sha.h"
#include "filters.h"
#include "hex.h"
#include "secblock.h"

#if defined(_WIN64) || defined(__linux__)
  #define X64
#endif


class CaplInstanceData;
typedef std::map<uint32_t, CaplInstanceData*> VCaplMap;
typedef std::map<uint32_t, VIACapl*> VServiceMap;


// ============================================================================
// global variables
// ============================================================================

static uint32_t data = 0;
static char dlldata[100];

VCaplMap    gCaplMap;
VServiceMap gServiceMap;


// ============================================================================
// CaplInstanceData
//
// Data local for a single CAPL Block.
//
// A CAPL-DLL can be used by more than one CAPL-Block, so every piece of
// information thats like a global variable in CAPL, must now be wrapped into
// an instance of an object.
// ============================================================================
class CaplInstanceData
{
public:
  CaplInstanceData(VIACapl* capl);

  void GetCallbackFunctions();
  void ReleaseCallbackFunctions();

  // Definition of the class function.
  // This class function will call the CAPL callback functions
  uint32_t ShowValue(uint32_t x);
  uint32_t ShowDates(int16_t x, uint32_t y, int16_t z);
  void     DllInfo(const char* x);
  void     ArrayValues(uint32_t flags, uint32_t numberOfDatabytes, uint8_t databytes[], uint8_t controlcode);
  void     DllVersion(const char* y);

private:

  // Pointer of the CAPL callback functions
  VIACaplFunction*  mShowValue;
  VIACaplFunction*  mShowDates;
  VIACaplFunction*  mDllInfo;
  VIACaplFunction*  mArrayValues;
  VIACaplFunction*  mDllVersion;

  VIACapl*          mCapl;
};


CaplInstanceData::CaplInstanceData(VIACapl* capl)
  // This function will initialize the CAPL callback function
  // with the NLL Pointer
 : mCapl(capl),
   mShowValue(nullptr),
   mShowDates(nullptr),
   mDllInfo(nullptr),
   mArrayValues(nullptr),
   mDllVersion(nullptr)
{}

static bool sCheckParams(VIACaplFunction* f, char rtype, const char* ptype)
{
  char      type;
  int32_t   pcount;
  VIAResult rc;

  // check return type
  rc = f->ResultType(&type);
  if (rc!=kVIA_OK || type!=rtype)
  {
    return false;
  }

  // check number of parameters
  rc = f->ParamCount(&pcount);
  if (rc!=kVIA_OK || strlen(ptype)!=pcount )
  {
    return false;
  }

  // check type of parameters
  for (int32_t i=0; i<pcount; ++i)
  {
    rc = f->ParamType(&type, i);
    if (rc!=kVIA_OK || type!=ptype[i])
    {
      return false;
    }
  }

  return true;
}

static VIACaplFunction* sGetCaplFunc(VIACapl* capl, const char* fname, char rtype, const char* ptype)
{
  VIACaplFunction* f;

  // get capl function object
  VIAResult rc =  capl->GetCaplFunction(&f, fname);
  if (rc!=kVIA_OK || f==nullptr)
  {
    return nullptr;
  }

  // check signature of function
  if ( sCheckParams(f, rtype, ptype) )
  {
     return f;
  }
  else
  {
    capl->ReleaseCaplFunction(f);
    return nullptr;
  }
}

void CaplInstanceData::GetCallbackFunctions()
{
  // Get a CAPL function handle. The handle stays valid until end of
  // measurement or a call of ReleaseCaplFunction.
  mShowValue   = sGetCaplFunc(mCapl, "CALLBACK_ShowValue", 'D', "D");
  mShowDates   = sGetCaplFunc(mCapl, "CALLBACK_ShowDates", 'D', "IDI");
  mDllInfo     = sGetCaplFunc(mCapl, "CALLBACK_DllInfo", 'V', "C");
  mArrayValues = sGetCaplFunc(mCapl, "CALLBACK_ArrayValues", 'V', "DBB");
  mDllVersion  = sGetCaplFunc(mCapl, "CALLBACK_DllVersion", 'V', "C");
}

void CaplInstanceData::ReleaseCallbackFunctions()
{
  // Release all the requested Callback functions
  mCapl->ReleaseCaplFunction(mShowValue);
  mShowValue = nullptr;
  mCapl->ReleaseCaplFunction(mShowDates);
  mShowDates = nullptr;
  mCapl->ReleaseCaplFunction(mDllInfo);
  mDllInfo = nullptr;
  mCapl->ReleaseCaplFunction(mArrayValues);
  mArrayValues = nullptr;
  mCapl->ReleaseCaplFunction(mDllVersion);
  mDllVersion = nullptr;
}

void CaplInstanceData::DllVersion(const char* y)
{
  // Prepare the parameters for the call stack of CAPL.
  // Arrays uses a 8 byte (64 bit DLL: 12 byte) on the stack, 4 Bytes for the number of element,
  // and 4 bytes (64 bit DLL: 8 byte) for the pointer to the array
  int32_t sizeX = (int32_t)strlen(y)+1;

#if defined(X64)
  uint8_t params[16];              // parameters for call stack, 16 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params+8, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+0, &y,     8);   // array pointer of first parameter, 8 Bytes
#else
  uint8_t params[8];               // parameters for call stack, 8 Bytes total
  memcpy(params+0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+4, &y,     4);   // array pointer of first parameter, 4 Bytes
#endif

  if(mDllVersion!=nullptr)
  {
    uint32_t result; // dummy variable
    VIAResult rc =  mDllVersion->Call(&result, params);
  }
}


uint32_t CaplInstanceData::ShowValue(uint32_t x)
{
#if defined(X64)
  uint8_t params[8];               // parameters for call stack, 8 Bytes total
  memcpy(params + 0, &x, 8);     // first parameter, 8 Bytes
#else
  void* params = &x;   // parameters for call stack
#endif

  uint32_t result;

  if(mShowValue!=nullptr)
  {
    VIAResult rc =  mShowValue->Call(&result, params);
    if (rc==kVIA_OK)
    {
       return result;
    }
  }
  return -1;
}

uint32_t CaplInstanceData::ShowDates(int16_t x, uint32_t y, int16_t z)
{
  // Prepare the parameters for the call stack of CAPL. The stack grows
  // from top to down, so the first parameter in the parameter list is the last
  // one in memory. CAPL uses also a 32 bit alignment for the parameters.

#if defined(X64)
  uint8_t params[24];          // parameters for call stack, 24 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params+16, &z, 2);  // third  parameter, offset 16, 2 Bytes
  memcpy(params+ 8, &y, 4);  // second parameter, offset 8,  4 Bytes
  memcpy(params+ 0, &x, 2);  // first  parameter, offset 0,  2 Bytes
#else
  uint8_t params[12];         // parameters for call stack, 12 Bytes total
  memcpy(params+0, &z, 2);  // third  parameter, offset 0, 2 Bytes
  memcpy(params+4, &y, 4);  // second parameter, offset 4, 4 Bytes
  memcpy(params+8, &x, 2);  // first  parameter, offset 8, 2 Bytes
#endif

  uint32_t result;

  if(mShowDates!=nullptr)
  {
    VIAResult rc =  mShowDates->Call(&result, params);
    if (rc==kVIA_OK)
    {
       return rc;   // call successful
    }
  }

  return -1; // call failed
}

void CaplInstanceData::DllInfo(const char* x)
{
  // Prepare the parameters for the call stack of CAPL.
  // Arrays uses a 8 byte (64 bit DLL: 12 byte) on the stack, 4 Bytes for the number of element,
  // and 4 bytes (64 bit DLL: 8 byte) for the pointer to the array
  int32_t sizeX = (int32)strlen(x)+1;

#if defined(X64)
  uint8_t params[16];              // parameters for call stack, 16 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params+8, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+0, &x,     8);   // array pointer of first parameter, 8 Bytes
#else
  uint8_t params[8];               // parameters for call stack, 8 Bytes total
  memcpy(params+0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+4, &x,     4);   // array pointer of first parameter, 4 Bytes
#endif

  if(mDllInfo!=nullptr)
  {
    uint32_t result; // dummy variable
    VIAResult rc =  mDllInfo->Call(&result, params);
  }
}

void CaplInstanceData::ArrayValues(uint32_t flags, uint32_t numberOfDatabytes, uint8_t databytes[], uint8_t controlcode)
{
  // Prepare the parameters for the call stack of CAPL. The stack grows
  // from top to down, so the first parameter in the parameter list is the last
  // one in memory. CAPL uses also a 32 bit alignment for the parameters.
  // Arrays uses a 8 byte (64 bit DLL: 12 byte) on the stack, 4 Bytes for the number of element,
  // and 4 bytes (64 bit DLL: 8 byte) for the pointer to the array

#if defined(X64)
  uint8_t params[32];                           // parameters for call stack, 32 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params+24, &controlcode,       1);   // third parameter,                  offset 24, 1 Bytes
  memcpy(params+16, &numberOfDatabytes, 4);   // second parameter (array size),    offset 16, 4 Bytes
  memcpy(params+ 8, &databytes,         8);   // second parameter (array pointer), offset  8, 8 Bytes
  memcpy(params+ 0, &flags,             4);   // first  parameter,                 offset  0, 4 Bytes
#else
  uint8_t params[16];                           // parameters for call stack, 16 Bytes total
  memcpy(params+ 0, &controlcode,       1);   // third parameter,                  offset  0, 1 Bytes
  memcpy(params+ 4, &numberOfDatabytes, 4);   // second parameter (array size),    offset  4, 4 Bytes
  memcpy(params+ 8, &databytes,         4);   // second parameter (array pointer), offset  8, 4 Bytes
  memcpy(params+12, &flags,             4);   // first  parameter,                 offset 12, 4 Bytes
#endif

  if(mArrayValues!=nullptr)
  {
    uint32_t result; // dummy variable
    VIAResult rc =  mArrayValues ->Call(&result, params);
  }

}

CaplInstanceData* GetCaplInstanceData(uint32_t handle)
{
  VCaplMap::iterator lSearchResult(gCaplMap.find(handle));
  if ( gCaplMap.end()==lSearchResult )
  {
    return nullptr;
  } 
  else 
  {
    return lSearchResult->second;
  }
}

// ============================================================================
// CaplInstanceData
//
// Data local for a single CAPL Block.
//
// A CAPL-DLL can be used by more than one CAPL-Block, so every piece of
// information thats like a global variable in CAPL, must now be wrapped into
// an instance of an object.
// ============================================================================

void CAPLEXPORT CAPLPASCAL appInit (uint32_t handle)
{
  CaplInstanceData* instance = GetCaplInstanceData(handle);
  if ( nullptr==instance )
  {
    VServiceMap::iterator lSearchService(gServiceMap.find(handle));
    if ( gServiceMap.end()!=lSearchService )
    {
      VIACapl* service = lSearchService->second;
      try
      {
        instance = new CaplInstanceData(service);
      }
      catch ( std::bad_alloc& )
      {
        return; // proceed without change
      }
      instance->GetCallbackFunctions();
      gCaplMap[handle] = instance;
    }
  }
}

void CAPLEXPORT CAPLPASCAL appEnd (uint32_t handle)
{
  CaplInstanceData* inst = GetCaplInstanceData(handle);
  if (inst==nullptr)
  {
    return;
  }
  inst->ReleaseCallbackFunctions();

  delete inst;
  inst = nullptr;
  gCaplMap.erase(handle);
}

// ============================================================================
// VIARegisterCDLL
// ============================================================================

VIACLIENT(void) VIARegisterCDLL (VIACapl* service)
{
  uint32_t  handle;
  VIAResult result;

  if (service==nullptr)
  {
    return;
  }

  result = service->GetCaplHandle(&handle);
  if(result!=kVIA_OK)
  {
    return;
  }

  // appInit (internal) resp. "DllInit" (CAPL code) has to follow
  gServiceMap[handle] = service;
}

void ClearAll()
{
  // destroy objects created by this DLL
  // may result from forgotten DllEnd calls
  VCaplMap::iterator lIter=gCaplMap.begin();
  const int32_t cNumberOfEntries = (int32_t)gCaplMap.size();
  int32_t i = 0;
  while ( lIter!=gCaplMap.end() && i<cNumberOfEntries )
  {
    appEnd( (*lIter).first );
    lIter = gCaplMap.begin(); // first element should have vanished
    i++; // assure that no more erase trials take place than the original size of the map
  }

  // just for clarity (would be done automatically)
  gCaplMap.clear();
  gServiceMap.clear();
}

int32_t CAPLEXPORT CAPLPASCAL appAdd(int32_t x, int32_t y)
{
  int32_t z = x + y;

  return z;
}

#define EightLongPars 'L','L','L','L','L','L','L','L'
#define SixtyFourLongPars EightLongPars,EightLongPars,EightLongPars,EightLongPars,EightLongPars,EightLongPars,EightLongPars,EightLongPars

// ----------------------- 以下为新增加函数 ------------------------- //
/**
 * @brief 使用指定的十六进制私钥对 C-风格字符串进行 RSASSA-PSS 签名。
 *
 * @param privateKeyHex       十六进制格式的私钥字符串。
 * @param message             要签名的 C-风格字符串。
 * @param signature_out       用于存储签名结果的字节数组。
 * @param signature_out_len   签名数组的缓冲区大小。
 * @return size_t             签名成功则返回实际签名长度；失败则返回0。
 */
size_t CAPLEXPORT CAPLPASCAL RSASignMessage(const char* privateKeyHex, const char* message, CryptoPP::byte* signature_out, size_t signature_out_len) {
    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        // 使用 RSASS<PSSR, SHA256> 签名器
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer signer(privateKey);

        // 直接将原始消息和长度传递给签名函数，库会自动进行哈希
        CryptoPP::SecByteBlock signature(signer.MaxSignatureLength());
        size_t signed_len = signer.SignMessage(
            rng,
            reinterpret_cast<const CryptoPP::byte*>(message),
            strlen(message),
            signature
        );

        if (signature_out_len < signed_len) {
            std::cerr << "错误：提供的缓冲区太小。所需大小为: " << signed_len << " 字节。" << std::endl;
            return 0;
        }

        memcpy(signature_out, signature.data(), signed_len);
        return signed_len;

    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ 签名异常: " << e.what() << std::endl;
        return 0;
    }
}

/**
 * @brief 使用指定的十六进制私钥对字节数组进行 RSASSA-PSS 签名。
 *
 * @param privateKeyHex       十六进制格式的私钥字符串。
 * @param message             要签名的字节数组。
 * @param messageLen          消息的长度。
 * @param signature_out       用于存储签名结果的字节数组。
 * @param signature_out_len   签名数组的缓冲区大小。
 * @return size_t             签名成功则返回实际签名长度；失败则返回0。
 */
size_t CAPLEXPORT CAPLPASCAL RSASignByteArray(const char* privateKeyHex, const CryptoPP::byte* message, size_t messageLen, CryptoPP::byte* signature_out, size_t signature_out_len) {
    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer signer(privateKey);

        // 直接将原始消息和长度传递给签名函数，库会自动进行哈希
        CryptoPP::SecByteBlock signature(signer.MaxSignatureLength());
        size_t signed_len = signer.SignMessage(
            rng,
            message,
            messageLen,
            signature
        );

        if (signature_out_len < signed_len) {
            std::cerr << "错误：提供的缓冲区太小。所需大小为: " << signed_len << " 字节。" << std::endl;
            return 0;
        }

        memcpy(signature_out, signature.data(), signed_len);
        return signed_len;

    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ 签名异常: " << e.what() << std::endl;
        return 0;
    }
}

// 提取公钥参数的函数
// 如果成功，返回一个非零值；如果失败，返回 0。
size_t CAPLEXPORT CAPLPASCAL ExtractPublicKeyParams(
    const char* privateKeyHex,
    byte* modulusBytes,
    size_t& modulusLength,
    byte* publicExponentBytes,
    size_t& publicExponentLength) {
    try {
        CryptoPP::HexDecoder hexDecoder;
        hexDecoder.Put(reinterpret_cast<const byte*>(privateKeyHex), strlen(privateKeyHex));
        hexDecoder.MessageEnd();

        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.Load(hexDecoder);

        CryptoPP::Integer modulus = privateKey.GetModulus();
        CryptoPP::Integer publicExponent = privateKey.GetPublicExponent();

        // 将长度赋给引用参数
        modulusLength = modulus.MinEncodedSize();
        publicExponentLength = publicExponent.MinEncodedSize();

        // 编码数据到调用者提供的缓冲区中
        modulus.Encode(modulusBytes, modulusLength);
        publicExponent.Encode(publicExponentBytes, publicExponentLength);

        return 1; // 成功时返回非零值
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        // 失败时，将长度设置为 0
        modulusLength = 0;
        publicExponentLength = 0;
        return 0; // 失败时返回 0
    }
}

// ============================================================================
// CAPL_DLL_INFO_LIST : list of exported functions
//   The first field is predefined and mustn't be changed!
//   The list has to end with a {0,0} entry!
// New struct supporting function names with up to 50 characters
// ============================================================================
CAPL_DLL_INFO4 table[] = {
{CDLL_VERSION_NAME, (CAPL_FARCALL)CDLL_VERSION, "", "", CAPL_DLL_CDECL, 0xabcd, CDLL_EXPORT },

  {"dllAdd", (CAPL_FARCALL)appAdd, "CAPL_DLL", "This function will add two values. The return value is the result", 'L', 2, "LL", "", {"x","y"}},
  {"dllRSASignMessage", (CAPL_FARCALL)RSASignMessage, "CAPL_DLL", "Sign the message string with RSASSA-PSS using the specified hexadecimal private key.", 'L', 4, "CCBL", "\001\001\001\000", {"privateKeyHex","message","signature_out","signature_out_len"}},
  {"dllRSASignByteArray", (CAPL_FARCALL)RSASignByteArray, "CAPL_DLL", "Sign a byte array using RSASSA-PSS with the specified hexadecimal private key.", 'L', 5, "CBLBL", "\001\001\000\001\000", {"privateKeyHex","message","messageLen","signature_out","signature_out_len"}},
  {"dllExtractPublicKeyParams", (CAPL_FARCALL)ExtractPublicKeyParams, "CAPL_DLL", "extract public key parameters from a C-style private key string", 'L', 5, {'C','B','L'-128,'B','L'-128}, "\001\001\000\001\000", {"privateKeyHex","modulusBytes","modulusLength","publicExponentBytes","publicExponentLength"}},
  {0, 0}
};
CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = table;




