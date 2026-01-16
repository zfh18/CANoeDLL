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
#include <map>
#include <new>
#include <ctime>

#include "rsa.h"
#include "osrng.h"
#include "pssr.h"
#include "sha.h"
#include "filters.h"
#include "hex.h"
#include "secblock.h"
#include "queue.h"
#include "oids.h"

#if defined(_WIN64) || defined(__linux__)
  #define X64
#endif


class CaplInstanceData;
typedef std::map<uint32_t, CaplInstanceData*> VCaplMap;
typedef std::map<uint32_t, VIACapl*> VServiceMap;


// ============================================================================
// global variables
// ============================================================================

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
 * @return size_t             签名成功则返回实际签名长度；失败则返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL RSASignMessage(const char* privateKeyHex, const char* message, CryptoPP::byte* signature_out, size_t signature_out_len) {
    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        // 使用 RSASS<PSSR, SHA256> 签名
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
            return 0;
        }

        memcpy(signature_out, signature.data(), signed_len);
        return signed_len;

    }
    catch (const CryptoPP::Exception&) {
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
 * @return size_t             签名成功则返回实际签名长度；失败则返回 0。
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
            return 0;
        }

        memcpy(signature_out, signature.data(), signed_len);
        return signed_len;

    }
    catch (const CryptoPP::Exception&) {
        return 0;
    }
}

/**
 * @brief 计算输入数据的 SHA-256 哈希值。
 *
 * @param message             输入的字节数组。
 * @param messageLen          输入数据长度。
 * @param hash_out            输出哈希结果的字节数组（32 字节）。
 * @param hash_out_len        输出缓冲区大小。
 * @return size_t             成功返回 32；失败返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL Hash256(
    const CryptoPP::byte* message,
    size_t messageLen,
    CryptoPP::byte* hash_out,
    size_t hash_out_len) {
    if ((message == nullptr && messageLen > 0) || hash_out == nullptr) {
        return 0;
    }
    if (hash_out_len < CryptoPP::SHA256::DIGESTSIZE) {
        return 0;
    }

    CryptoPP::SHA256 hash;
    hash.Update(message, messageLen);
    hash.Final(hash_out);
    return CryptoPP::SHA256::DIGESTSIZE;
}

static bool BuildUtcTimeString(std::time_t timeValue, CryptoPP::SecByteBlock& out) {
    std::tm tmUtc;
    if (gmtime_s(&tmUtc, &timeValue) != 0) {
        return false;
    }

    char buffer[16] = {0};
    if (std::strftime(buffer, sizeof(buffer), "%y%m%d%H%M%SZ", &tmUtc) == 0) {
        return false;
    }

    out.Assign(reinterpret_cast<const CryptoPP::byte*>(buffer), std::strlen(buffer));
    return true;
}

static void EncodeName(CryptoPP::DERSequenceEncoder& out, const char* commonName) {
    CryptoPP::DERSequenceEncoder rdnSeq(out);
    CryptoPP::DERSetEncoder rdnSet(rdnSeq);
    CryptoPP::DERSequenceEncoder atv(rdnSet);

    CryptoPP::OID cnOid(2);
    cnOid += 5;
    cnOid += 4;
    cnOid += 3;
    cnOid.DEREncode(atv);

    CryptoPP::DEREncodeTextString(
        atv,
        reinterpret_cast<const CryptoPP::byte*>(commonName),
        std::strlen(commonName),
        CryptoPP::UTF8_STRING);

    atv.MessageEnd();
    rdnSet.MessageEnd();
    rdnSeq.MessageEnd();
}

/**
 * @brief 使用 RSA2048 + PKCS#1 v1.5 生成自签名 X.509 证书（DER）。
 *
 * @param privateKeyHex       十六进制格式的私钥字符串（PKCS#8 DER）。
 * @param subjectCN           证书主题/签发者的 CN。
 * @param daysValid           有效期天数（0 表示 365 天）。
 * @param cert_out            输出证书 DER 的缓冲区。
 * @param cert_out_len        输出缓冲区大小。
 * @return size_t             成功返回证书字节数；失败返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL GenerateX509Certificate(
    const char* privateKeyHex,
    const char* subjectCN,
    uint32_t daysValid,
    CryptoPP::byte* cert_out,
    size_t cert_out_len) {
    if (privateKeyHex == nullptr || subjectCN == nullptr || cert_out == nullptr) {
        return 0;
    }

    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        if (privateKey.GetModulus().BitCount() != 2048) {
            return 0;
        }

        CryptoPP::RSA::PublicKey publicKey(privateKey);
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::ByteQueue tbsQueue;
        {
            CryptoPP::DERSequenceEncoder tbsSeq(tbsQueue);

            CryptoPP::DERGeneralEncoder version(tbsSeq, CryptoPP::CONTEXT_SPECIFIC | CryptoPP::CONSTRUCTED | 0);
            CryptoPP::DEREncodeUnsigned(version, 2);
            version.MessageEnd();

            CryptoPP::DEREncodeUnsigned(tbsSeq, 1U);

            CryptoPP::DERSequenceEncoder sigAlg(tbsSeq);
            CryptoPP::ASN1::sha256WithRSAEncryption().DEREncode(sigAlg);
            CryptoPP::DEREncodeNull(sigAlg);
            sigAlg.MessageEnd();

            EncodeName(tbsSeq, subjectCN);

            const uint32_t effectiveDays = (daysValid == 0) ? 365U : daysValid;
            const std::time_t now = std::time(nullptr);
            const std::time_t notAfter = now + static_cast<std::time_t>(effectiveDays) * 24 * 60 * 60;

            CryptoPP::SecByteBlock notBeforeStr;
            CryptoPP::SecByteBlock notAfterStr;
            if (!BuildUtcTimeString(now, notBeforeStr) || !BuildUtcTimeString(notAfter, notAfterStr)) {
                return 0;
            }

            CryptoPP::DERSequenceEncoder validity(tbsSeq);
            CryptoPP::DEREncodeDate(validity, notBeforeStr, CryptoPP::UTC_TIME);
            CryptoPP::DEREncodeDate(validity, notAfterStr, CryptoPP::UTC_TIME);
            validity.MessageEnd();

            EncodeName(tbsSeq, subjectCN);
            publicKey.Save(tbsSeq);

            tbsSeq.MessageEnd();
        }

        CryptoPP::SecByteBlock tbsData(tbsQueue.CurrentSize());
        tbsQueue.Get(tbsData, tbsData.size());

        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(privateKey);
        CryptoPP::SecByteBlock signature(signer.MaxSignatureLength());
        size_t sigLen = signer.SignMessage(rng, tbsData, tbsData.size(), signature);

        CryptoPP::ByteQueue certQueue;
        {
            CryptoPP::DERSequenceEncoder certSeq(certQueue);
            certSeq.Put(tbsData, tbsData.size());

            CryptoPP::DERSequenceEncoder sigAlg(certSeq);
            CryptoPP::ASN1::sha256WithRSAEncryption().DEREncode(sigAlg);
            CryptoPP::DEREncodeNull(sigAlg);
            sigAlg.MessageEnd();

            CryptoPP::DEREncodeBitString(certSeq, signature.data(), sigLen, 0);
            certSeq.MessageEnd();
        }

        const size_t certLen = certQueue.CurrentSize();
        if (cert_out_len < certLen) {
            return 0;
        }

        certQueue.Get(cert_out, certLen);
        return certLen;
    }
    catch (const CryptoPP::Exception&) {
        return 0;
    }
}

/**
 * @brief 从私钥中提取 RSA 公钥参数（模数 n 与公钥指数 e）。
 *
 * 输入的私钥为 PKCS#8 DER 十六进制字符串。函数会解析私钥并输出：
 * - modulusBytes：模数 n 的大端字节序
 * - publicExponentBytes：公钥指数 e 的大端字节序
 *
 * @param privateKeyHex            十六进制格式的私钥字符串（PKCS#8 DER）。
 * @param modulusBytes             输出模数 n 的缓冲区。
 * @param modulusLength            输入为缓冲区大小，输出为实际长度。
 * @param publicExponentBytes      输出公钥指数 e 的缓冲区。
 * @param publicExponentLength     输入为缓冲区大小，输出为实际长度。
 * @return size_t                  成功返回 1；失败返回 0。
 */
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
    catch (const CryptoPP::Exception&) {
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

  {"dllRSASignMessage", (CAPL_FARCALL)RSASignMessage, "RSA", "Sign the message string with RSASSA-PSS using the specified hexadecimal private key.", 'L', 4, "CCBL", "\001\001\001\000", {"privateKeyHex","message","signature_out","signature_out_len"}},
  {"dllRSASignByteArray", (CAPL_FARCALL)RSASignByteArray, "RSA", "Sign a byte array using RSASSA-PSS with the specified hexadecimal private key.", 'L', 5, "CBLBL", "\001\001\000\001\000", {"privateKeyHex","message","messageLen","signature_out","signature_out_len"}},
  {"dllHash256", (CAPL_FARCALL)Hash256, "Algorithm", "Compute SHA-256 hash for a byte array.", 'L', 4, "BLBL", "\001\000\001\000", {"message","messageLen","hash_out","hash_out_len"}},
  {"dllGenerateX509Certificate", (CAPL_FARCALL)GenerateX509Certificate, "RSA", "Generate a self-signed RSA2048 X.509 certificate (DER).", 'L', 5, "CCLBL", "\001\001\000\001\000", {"privateKeyHex","subjectCN","daysValid","cert_out","cert_out_len"}},
  {"dllExtractPublicKeyParams", (CAPL_FARCALL)ExtractPublicKeyParams, "RSA", "extract public key parameters from a C-style private key string", 'L', 5, {'C','B','L'-128,'B','L'-128}, "\001\001\000\001\000", {"privateKeyHex","modulusBytes","modulusLength","publicExponentBytes","publicExponentLength"}},
  {0, 0}
};
CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = table;




