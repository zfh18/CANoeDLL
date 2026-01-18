#pragma once

#define USECDLL_FEATURE
#define _BUILDNODELAYERDLL

#include "../Includes/cdll.h"
#include "../Includes/VIA.h"
#include "../Includes/VIA_CDLL.h"

#include <stdint.h>
#include <string.h>
#include <map>
#include <new>

#if defined(_WIN64) || defined(__linux__)
#define X64
#endif

class CaplInstanceData
{
public:
  CaplInstanceData(VIACapl* capl);

  void GetCallbackFunctions();
  void ReleaseCallbackFunctions();

  uint32_t ShowValue(uint32_t x);
  uint32_t ShowDates(int16_t x, uint32_t y, int16_t z);
  void DllInfo(const char* x);
  void ArrayValues(uint32_t flags, uint32_t numberOfDatabytes, uint8_t databytes[], uint8_t controlcode);
  void DllVersion(const char* y);

private:
  VIACaplFunction* mShowValue;
  VIACaplFunction* mShowDates;
  VIACaplFunction* mDllInfo;
  VIACaplFunction* mArrayValues;
  VIACaplFunction* mDllVersion;

  VIACapl* mCapl;
};

typedef std::map<uint32_t, CaplInstanceData*> VCaplMap;
typedef std::map<uint32_t, VIACapl*> VServiceMap;

extern VCaplMap gCaplMap;
extern VServiceMap gServiceMap;

CaplInstanceData* GetCaplInstanceData(uint32_t handle);

void CAPLEXPORT CAPLPASCAL appInit(uint32_t handle);
void CAPLEXPORT CAPLPASCAL appEnd(uint32_t handle);
VIACLIENT(void) VIARegisterCDLL(VIACapl* service);
void ClearAll();
