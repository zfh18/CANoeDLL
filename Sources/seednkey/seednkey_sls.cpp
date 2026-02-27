// KeyGeneration.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include "KeyGenAlgoInterfaceEx.h"

#include <cstring>  // 引入 memcpy
#include <cryptlib.h>
#include <cmac.h>
#include <aes.h>

using namespace CryptoPP;


BOOL APIENTRY DllMain( HANDLE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

// F1L X1L mask
// 使用 AES-128 密钥（16字节）
const byte mask_app[16] = { 0xB4, 0x67, 0xA1, 0xC6, 0xD1, 0x17, 0xCC, 0x09, 0xD7, 0xC7, 0x8D, 0xE1, 0x81, 0xB9, 0x49, 0xB9 }; // 128 bit mask
const byte mask_boot[16] = { 0x2D, 0x52, 0x11, 0x45, 0xB8, 0x61, 0x59, 0xF5, 0x26, 0x31, 0x2E, 0x6E, 0xC3, 0x1C, 0x2A, 0x4E }; // 128 bit mask
const unsigned char LPmask[4] = { 0xC4, 0xA7, 0x96, 0xE5 };   // 来自零跑的 mask，用于计算 Lv61
byte mask[16] = {0x0};

KEYGENALGO_API VKeyGenResultEx GenerateKeyEx(
      const unsigned char*  iSeedArray,     /* Array for the seed [in] */
      unsigned int          iSeedArraySize, /* Length of the array for the seed [in] */
      const unsigned int    iSecurityLevel, /* Security level [in] */
      const char*           iVariant,       /* Name of the active variant [in] */
      unsigned char*        ioKeyArray,     /* Array for the key [in, out] */
      unsigned int          iKeyArraySize,  /* Maximum length of the array for the key [in] */
      unsigned int&         oSize           /* Length of the key [out] */
      )
{
    if (iSeedArraySize>iKeyArraySize)
      return KGRE_BufferToSmall;
    for (unsigned int i=0;i<iSeedArraySize;i++)
      ioKeyArray[i]=~iSeedArray[i];
    oSize=iSeedArraySize;

    // 不同 Level mask 不同
    if (0x01 == iSecurityLevel) // 扩展会话
    {
        memcpy(mask, mask_app, sizeof(mask_app));
    }
    else if (0x09 == iSecurityLevel)    // 编程会话
    {
        memcpy(mask, mask_boot, sizeof(mask_boot));
    }
    else  // Lv61，最新使用零跑算法
    {
        unsigned char tmpKey[4]{};
        for (int i = 0; i < 4; i++)
        {
            tmpKey[i] = iSeedArray[i] ^ LPmask[i];
        }
        ioKeyArray[0] = ((tmpKey[0] & 0x0f) << 4) | (tmpKey[1] & 0xf0);
        ioKeyArray[1] = ((tmpKey[1] & 0x0f) << 4) | ((tmpKey[2] & 0xf0) >> 4);
        ioKeyArray[2] = (tmpKey[2] & 0xf0) | ((tmpKey[3] & 0xf0) >> 4);
        ioKeyArray[3] = ((tmpKey[3] & 0x0f) << 4) | (tmpKey[0] & 0x0f);
    }
    if ((0x01 == iSecurityLevel) || (0x09 == iSecurityLevel))   // Lv1 和 Lv9，使用 CMAC(AES128) 算法
    {
        // 创建 CMAC 对象（使用 AES-128 密钥），具体算法如下
        CMAC<AES> cmac(mask, AES::DEFAULT_KEYLENGTH);  // 传递密钥和密钥长度

        // 要计算 CMAC 的消息，就是 iSeedArray 里的数据
        // 计算 CMAC 标签
        SecByteBlock mac(cmac.DigestSize());  // mac 存储 128 bit 的输出
        cmac.CalculateDigest(mac, iSeedArray, iSeedArraySize);  // 这里数据长度不要使用 sizeof(iSeedArray)，可能只会返回 4
        memcpy(ioKeyArray, mac, sizeof(mac));  // 复制所有字节
        // 算法结束
    }
    
    return KGRE_Ok;
}
