/*----------------------------------------------------------------------------
|
| File Name: cryptodll.cpp
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
// ============================================================================
// CaplInstanceData
//
// Data local for a single CAPL Block.
//
// A CAPL-DLL can be used by more than one CAPL-Block, so every piece of
// information thats like a global variable in CAPL, must now be wrapped into
// an instance of an object.
// ============================================================================
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
size_t CAPLEXPORT CAPLPASCAL RSASignMessagePSS(const char* privateKeyHex, const char* message, CryptoPP::byte* signature_out, size_t signature_out_len) {
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
 * @brief 使用指定的十六进制私钥对 C-风格字符串进行 RSA PKCS#1 v1.5 签名。
 *
 * @param privateKeyHex       十六进制格式的私钥字符串。
 * @param message             要签名的 C-风格字符串。
 * @param signature_out       用于存储签名结果的字节数组。
 * @param signature_out_len   签名数组的缓冲区大小。
 * @return size_t             签名成功则返回实际签名长度；失败则返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL RSASignMessagePKCS1(
    const char* privateKeyHex,
    const char* message,
    CryptoPP::byte* signature_out,
    size_t signature_out_len) {
    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(privateKey);

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
size_t CAPLEXPORT CAPLPASCAL RSASignByteArrayPSS(const char* privateKeyHex, const CryptoPP::byte* message, size_t messageLen, CryptoPP::byte* signature_out, size_t signature_out_len) {
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
 * @brief 使用指定的十六进制私钥对字节数组进行 RSA PKCS#1 v1.5 签名。
 *
 * @param privateKeyHex       十六进制格式的私钥字符串。
 * @param message             要签名的字节数组。
 * @param messageLen          消息的长度。
 * @param signature_out       用于存储签名结果的字节数组。
 * @param signature_out_len   签名数组的缓冲区大小。
 * @return size_t             签名成功则返回实际签名长度；失败则返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL RSASignByteArrayPKCS1(
    const char* privateKeyHex,
    const CryptoPP::byte* message,
    size_t messageLen,
    CryptoPP::byte* signature_out,
    size_t signature_out_len) {
    try {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::StringSource ssPrivate(privateKeyHex, true, new CryptoPP::HexDecoder);
        privateKey.Load(ssPrivate);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(privateKey);

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
 * @brief 使用 RSA + PKCS#1 v1.5 生成自签名 X.509 证书（DER）。
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

  {"dllRSASignMessagePSS", (CAPL_FARCALL)RSASignMessagePSS, "RSA", "Sign the message string with RSASSA-PSS using the specified hexadecimal private key.", 'L', 4, "CCBL", "\001\001\001\000", {"privateKeyHex","message","signature_out","signature_out_len"}},
  {"dllRSASignMessagePKCS1", (CAPL_FARCALL)RSASignMessagePKCS1, "RSA", "Sign the message string with RSA PKCS#1 v1.5 using the specified hexadecimal private key.", 'L', 4, "CCBL", "\001\001\001\000", {"privateKeyHex","message","signature_out","signature_out_len"}},
  {"dllRSASignByteArrayPSS", (CAPL_FARCALL)RSASignByteArrayPSS, "RSA", "Sign a byte array using RSASSA-PSS with the specified hexadecimal private key.", 'L', 5, "CBLBL", "\001\001\000\001\000", {"privateKeyHex","message","messageLen","signature_out","signature_out_len"}},
  {"dllRSASignByteArrayPKCS1", (CAPL_FARCALL)RSASignByteArrayPKCS1, "RSA", "Sign a byte array with RSA PKCS#1 v1.5 using the specified hexadecimal private key.", 'L', 5, "CBLBL", "\001\001\000\001\000", {"privateKeyHex","message","messageLen","signature_out","signature_out_len"}},
  {"dllHash256", (CAPL_FARCALL)Hash256, "Algorithm", "Compute SHA-256 hash for a byte array.", 'L', 4, "BLBL", "\001\000\001\000", {"message","messageLen","hash_out","hash_out_len"}},
  {"dllGenerateX509Certificate", (CAPL_FARCALL)GenerateX509Certificate, "RSA", "Generate a self-signed RSA X.509 certificate (DER).", 'L', 5, "CCLBL", "\001\001\000\001\000", {"privateKeyHex","subjectCN","daysValid","cert_out","cert_out_len"}},
  {"dllExtractPublicKeyParams", (CAPL_FARCALL)ExtractPublicKeyParams, "RSA", "extract public key parameters from a C-style private key string", 'L', 5, {'C','B','L'-128,'B','L'-128}, "\001\001\000\001\000", {"privateKeyHex","modulusBytes","modulusLength","publicExponentBytes","publicExponentLength"}},
  {0, 0}
};
CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = table;
