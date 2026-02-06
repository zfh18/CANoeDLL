/*----------------------------------------------------------------------------
|
| File Name: SecurityAlgo.cpp
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

#include "aes.h"
#include "cmac.h"

// ----------------------- 以下为新增加函数 ------------------------- //
static uint32_t SwapU32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) |
           ((value & 0x0000FF00u) << 8)  |
           ((value & 0x00FF0000u) >> 8)  |
           ((value & 0xFF000000u) >> 24);
}

static uint32_t Rotl32(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32u - bits));
}

static void StoreU32BE(uint32_t value, CryptoPP::byte* out) {
    out[0] = static_cast<CryptoPP::byte>((value >> 24) & 0xFF);
    out[1] = static_cast<CryptoPP::byte>((value >> 16) & 0xFF);
    out[2] = static_cast<CryptoPP::byte>((value >> 8) & 0xFF);
    out[3] = static_cast<CryptoPP::byte>(value & 0xFF);
}

/**
 * @brief 计算 CMAC-AES（支持 128/192/256 位密钥）。
 *
 * @param key                密钥字节数组（16/24/32 字节）。
 * @param keyLen             密钥长度，必须为 16/24/32。
 * @param message            输入数据字节数组。
 * @param messageLen         输入数据长度。
 * @param mac_out            输出 CMAC（固定 16 字节）。
 * @param mac_out_len        输出缓冲区大小（至少 16）。
 * @return size_t            成功返回 16；失败返回 0。
 */
size_t CAPLEXPORT CAPLPASCAL CMACAES(
    const CryptoPP::byte* key,
    size_t keyLen,
    const CryptoPP::byte* message,
    size_t messageLen,
    CryptoPP::byte* mac_out,
    size_t mac_out_len) {
    if (key == nullptr || mac_out == nullptr) {
        return 0;
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return 0;
    }
    if (message == nullptr && messageLen > 0) {
        return 0;
    }
    if (mac_out_len < CryptoPP::AES::BLOCKSIZE) {
        return 0;
    }

    CryptoPP::CMAC<CryptoPP::AES> cmac;
    cmac.SetKey(key, keyLen);
    cmac.Update(message, messageLen);
    cmac.Final(mac_out);
    return CryptoPP::AES::BLOCKSIZE;
}

/**
 * @brief SecAlgo LT: level 0x01/0x09, 4-byte seed/key, mask required.
 */
size_t CAPLEXPORT CAPLPASCAL SecAlgoLTCalcKeyFromSeed(
    const CryptoPP::byte* seed,
    size_t seedLen,
    uint32_t level,
    const CryptoPP::byte* mask,
    size_t maskLen,
    CryptoPP::byte* key_out,
    size_t key_out_len) {
    if (seed == nullptr || mask == nullptr || key_out == nullptr) {
        return 0;
    }
    if (seedLen < 4 || maskLen < 4 || key_out_len < 4) {
        return 0;
    }
    if (level != 0x01 && level != 0x09) {
        return 0;
    }

    CryptoPP::byte tmpKey[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        tmpKey[i] = static_cast<CryptoPP::byte>(seed[i] ^ mask[i]);
    }

    if (level == 0x09) {
        key_out[0] = static_cast<CryptoPP::byte>(((tmpKey[0] & 0x0F) << 4) | (tmpKey[1] & 0x0F));
        key_out[1] = static_cast<CryptoPP::byte>(((tmpKey[1] & 0xF0) >> 4) | ((tmpKey[2] & 0x0F) << 4));
        key_out[2] = static_cast<CryptoPP::byte>(((tmpKey[2] & 0xF0) >> 4) | (tmpKey[3] & 0xF0));
        key_out[3] = static_cast<CryptoPP::byte>((tmpKey[3] & 0x0F) | ((tmpKey[0] & 0xF0) >> 4));
    } else {
        key_out[0] = static_cast<CryptoPP::byte>(((tmpKey[0] & 0x0F) << 4) | (tmpKey[1] & 0xF0));
        key_out[1] = static_cast<CryptoPP::byte>(((tmpKey[1] & 0x0F) << 4) | ((tmpKey[2] & 0xF0) >> 4));
        key_out[2] = static_cast<CryptoPP::byte>((tmpKey[2] & 0xF0) | ((tmpKey[3] & 0xF0) >> 4));
        key_out[3] = static_cast<CryptoPP::byte>(((tmpKey[3] & 0x0F) << 4) | (tmpKey[0] & 0x0F));
    }

    return 4;
}

/**
 * @brief SecAlgo SLS: CMAC(AES128), 16-byte seed/key, 16-byte mask.
 */
size_t CAPLEXPORT CAPLPASCAL SecAlgoSLSCalcKeyFromSeed(
    const CryptoPP::byte* seed,
    size_t seedLen,
    const CryptoPP::byte* mask,
    size_t maskLen,
    CryptoPP::byte* key_out,
    size_t key_out_len) {
    if (seed == nullptr || mask == nullptr || key_out == nullptr) {
        return 0;
    }
    if (seedLen < 16 || maskLen < 16 || key_out_len < 16) {
        return 0;
    }
    return CMACAES(mask, 16, seed, seedLen, key_out, key_out_len);
}

/**
 * @brief SecAlgo LP: level 0x01/0x11, 4-byte seed/key.
 */
size_t CAPLEXPORT CAPLPASCAL SecAlgoLPCalcKeyFromSeed(
    const CryptoPP::byte* seed,
    size_t seedLen,
    uint32_t level,
    CryptoPP::byte* key_out,
    size_t key_out_len) {
    if (seed == nullptr || key_out == nullptr) {
        return 0;
    }
    if (seedLen < 4 || key_out_len < 4) {
        return 0;
    }
    if (level != 0x01 && level != 0x11) {
        return 0;
    }

    uint32_t seedTmp = (static_cast<uint32_t>(seed[0]) << 24) |
                       (static_cast<uint32_t>(seed[1]) << 16) |
                       (static_cast<uint32_t>(seed[2]) << 8)  |
                       static_cast<uint32_t>(seed[3]);
    uint32_t keyTmp = 0;

    if (level == 0x01) {
        keyTmp = (((seedTmp >> 4) ^ seedTmp) << 3) ^ seedTmp;
    } else {
        uint32_t mask[4] = {0x4fe87269u, 0x6bc361d8u, 0x9b127d51u, 0x5ba41903u};
        uint32_t y = SwapU32(seedTmp);
        uint32_t z = 0;
        uint32_t sum = 0;
        uint8_t n = 64;
        while (n > 0) {
            y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + mask[sum & 3u]);
            sum += 0x8f750a1du;
            z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + mask[(sum >> 11) & 3u]);
            n--;
        }
        keyTmp = SwapU32(z);
    }

    StoreU32BE(keyTmp, key_out);
    return 4;
}

/**
 * @brief SecAlgo QR: level 0x01/0x03/0x05/0x07, 4-byte seed/key.
 */
size_t CAPLEXPORT CAPLPASCAL SecAlgoQRCalcKeyFromSeed(
    const CryptoPP::byte* seed,
    size_t seedLen,
    uint32_t level,
    CryptoPP::byte* key_out,
    size_t key_out_len) {
    if (seed == nullptr || key_out == nullptr) {
        return 0;
    }
    if (seedLen < 4 || key_out_len < 4) {
        return 0;
    }

    uint32_t seedTmp = (static_cast<uint32_t>(seed[0]) << 24) |
                       (static_cast<uint32_t>(seed[1]) << 16) |
                       (static_cast<uint32_t>(seed[2]) << 8)  |
                       static_cast<uint32_t>(seed[3]);

    uint32_t lv1Mask = 0x6DD7u;
    uint32_t lv3Mask = 0xE9BAu;
    uint32_t lv5Mask = 0x17BAu;
    uint32_t lv7Mask = 0xAD91u;

    uint32_t keyTmp = 0;
    uint32_t v5 = 0;
    uint32_t index = 0;

    switch (level) {
    case 1:
        keyTmp = lv1Mask ^ seedTmp;
        for (index = 0; index < 0x20; ++index) {
            if ((keyTmp & 1u) != 0) {
                keyTmp = seedTmp ^ Rotl32(keyTmp, 3);
            } else {
                keyTmp = lv1Mask ^ Rotl32(keyTmp, 25);
            }
        }
        break;
    case 3:
        keyTmp = lv3Mask ^ seedTmp;
        for (index = 0; index < 0x20; ++index) {
            if ((keyTmp & 1u) != 0) {
                keyTmp = seedTmp ^ (keyTmp >> 1);
            } else {
                keyTmp = lv3Mask ^ (keyTmp >> 1);
            }
        }
        break;
    case 5:
        keyTmp = lv5Mask ^ seedTmp;
        for (index = 0; index < 0x20; ++index) {
            if ((seedTmp & 0x80000000u) == 0) {
                v5 = (seedTmp << 9) ^ (seedTmp >> 3);
            } else {
                v5 = (seedTmp >> 3) ^ (8u * (seedTmp ^ (seedTmp >> 1)));
            }
            keyTmp = lv5Mask ^ v5;
        }
        keyTmp = Rotl32(keyTmp, 15);
        break;
    case 7:
        keyTmp = lv7Mask ^ seedTmp;
        for (index = 0; index < 0x20; ++index) {
            keyTmp = lv7Mask ^ Rotl32(keyTmp, 7);
        }
        break;
    default:
        return 0;
    }

    StoreU32BE(keyTmp, key_out);
    return 4;
}

// ============================================================================
// CAPL_DLL_INFO_LIST : list of exported functions
//   The first field is predefined and mustn't be changed!
//   The list has to end with a {0,0} entry!
// New struct supporting function names with up to 50 characters
// ============================================================================
CAPL_DLL_INFO4 table[] = {
{CDLL_VERSION_NAME, (CAPL_FARCALL)CDLL_VERSION, "", "", CAPL_DLL_CDECL, 0xabcd, CDLL_EXPORT },

  {"dllSecAlgoLTCalcKeyFromSeed", (CAPL_FARCALL)SecAlgoLTCalcKeyFromSeed, "SecurityAlgo", "LT 0x27 key calc (seed 4, key 4, mask 4, level 0x01/0x09).", 'L', 7, "BLBLBLD", "\001\000\001\000\001\000\000", {"seed","seedLen","mask","maskLen","key_out","key_out_len","level"}},
  {"dllSecAlgoSLSCalcKeyFromSeed", (CAPL_FARCALL)SecAlgoSLSCalcKeyFromSeed, "SecurityAlgo", "SLS 0x27 key calc (CMAC-AES128).", 'L', 6, "BLBLBL", "\001\000\001\000\001\000", {"seed","seedLen","mask","maskLen","key_out","key_out_len"}},
  {"dllSecAlgoLPCalcKeyFromSeed", (CAPL_FARCALL)SecAlgoLPCalcKeyFromSeed, "SecurityAlgo", "LP 0x27 key calc (seed 4, key 4, level 0x01/0x11).", 'L', 5, "BLBLD", "\001\000\001\000\000", {"seed","seedLen","key_out","key_out_len","level"}},
  {"dllSecAlgoQRCalcKeyFromSeed", (CAPL_FARCALL)SecAlgoQRCalcKeyFromSeed, "SecurityAlgo", "QR 0x27 key calc (seed 4, key 4, level 0x01/0x03/0x05/0x07).", 'L', 5, "BLBLD", "\001\000\001\000\000", {"seed","seedLen","key_out","key_out_len","level"}},
  {0, 0}
};
CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = table;
