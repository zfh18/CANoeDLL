#include "capl_common.h"

VCaplMap gCaplMap;
VServiceMap gServiceMap;

static bool sCheckParams(VIACaplFunction* f, char rtype, const char* ptype)
{
  char      type;
  int32_t   pcount;
  VIAResult rc;

  // check return type
  rc = f->ResultType(&type);
  if (rc != kVIA_OK || type != rtype)
  {
    return false;
  }

  // check number of parameters
  rc = f->ParamCount(&pcount);
  if (rc != kVIA_OK || strlen(ptype) != pcount)
  {
    return false;
  }

  // check type of parameters
  for (int32_t i = 0; i < pcount; ++i)
  {
    rc = f->ParamType(&type, i);
    if (rc != kVIA_OK || type != ptype[i])
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
  VIAResult rc = capl->GetCaplFunction(&f, fname);
  if (rc != kVIA_OK || f == nullptr)
  {
    return nullptr;
  }

  // check signature of function
  if (sCheckParams(f, rtype, ptype))
  {
     return f;
  }
  else
  {
    capl->ReleaseCaplFunction(f);
    return nullptr;
  }
}

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
  int32_t sizeX = (int32_t)strlen(y) + 1;

#if defined(X64)
  uint8_t params[16];              // parameters for call stack, 16 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params + 8, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params + 0, &y, 8);   // array pointer of first parameter, 8 Bytes
#else
  uint8_t params[8];               // parameters for call stack, 8 Bytes total
  memcpy(params + 0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params + 4, &y, 4);   // array pointer of first parameter, 4 Bytes
#endif

  if (mDllVersion != nullptr)
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

  if (mShowValue != nullptr)
  {
    VIAResult rc =  mShowValue->Call(&result, params);
    if (rc == kVIA_OK)
    {
       return result;
    }
  }
  return static_cast<uint32_t>(-1);
}

uint32_t CaplInstanceData::ShowDates(int16_t x, uint32_t y, int16_t z)
{
  // Prepare the parameters for the call stack of CAPL. The stack grows
  // from top to down, so the first parameter in the parameter list is the last
  // one in memory. CAPL uses also a 32 bit alignment for the parameters.

#if defined(X64)
  uint8_t params[24];          // parameters for call stack, 24 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params + 16, &z, 2);  // third  parameter, offset 16, 2 Bytes
  memcpy(params +  8, &y, 4);  // second parameter, offset 8,  4 Bytes
  memcpy(params +  0, &x, 2);  // first  parameter, offset 0,  2 Bytes
#else
  uint8_t params[12];          // parameters for call stack, 12 Bytes total
  memcpy(params +  0, &z, 2);  // third  parameter, offset 0, 2 Bytes
  memcpy(params +  4, &y, 4);  // second parameter, offset 4, 4 Bytes
  memcpy(params +  8, &x, 2);  // first  parameter, offset 8, 2 Bytes
#endif

  uint32_t result;

  if (mShowDates != nullptr)
  {
    VIAResult rc =  mShowDates->Call(&result, params);
    if (rc == kVIA_OK)
    {
      return result;
    }
  }
  return static_cast<uint32_t>(-1);
}

void CaplInstanceData::DllInfo(const char* x)
{
  // Prepare the parameters for the call stack of CAPL.
  // Arrays uses a 8 byte (64 bit DLL: 12 byte) on the stack, 4 Bytes for the number of element,
  // and 4 bytes (64 bit DLL: 8 byte) for the pointer to the array
  int32_t sizeX = (int32_t)strlen(x) + 1;

#if defined(X64)
  uint8_t params[16];              // parameters for call stack, 16 Bytes total (8 bytes per parameter, reverse order of parameters)
  memcpy(params + 8, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params + 0, &x, 8);   // array pointer of first parameter, 8 Bytes
#else
  uint8_t params[8];               // parameters for call stack, 8 Bytes total
  memcpy(params + 0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params + 4, &x, 4);   // array pointer of first parameter, 4 Bytes
#endif

  if (mDllInfo != nullptr)
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
  memcpy(params + 24, &controlcode, 1);       // third parameter,                  offset 24, 1 Bytes
  memcpy(params + 16, &numberOfDatabytes, 4); // second parameter (array size),    offset 16, 4 Bytes
  memcpy(params +  8, &databytes, 8);         // second parameter (array pointer), offset  8, 8 Bytes
  memcpy(params +  0, &flags, 4);             // first  parameter,                 offset  0, 4 Bytes
#else
  uint8_t params[16];                           // parameters for call stack, 16 Bytes total
  memcpy(params +  0, &controlcode, 1);       // third parameter,                  offset  0, 1 Bytes
  memcpy(params +  4, &numberOfDatabytes, 4); // second parameter (array size),    offset  4, 4 Bytes
  memcpy(params +  8, &databytes, 4);         // second parameter (array pointer), offset  8, 4 Bytes
  memcpy(params + 12, &flags, 4);             // first  parameter,                 offset 12, 4 Bytes
#endif

  if (mArrayValues != nullptr)
  {
    uint32_t result; // dummy variable
    VIAResult rc =  mArrayValues->Call(&result, params);
  }
}

CaplInstanceData* GetCaplInstanceData(uint32_t handle)
{
  VCaplMap::iterator lSearchResult(gCaplMap.find(handle));
  if (gCaplMap.end() == lSearchResult)
  {
    return nullptr;
  }
  else
  {
    return lSearchResult->second;
  }
}

void CAPLEXPORT CAPLPASCAL appInit(uint32_t handle)
{
  CaplInstanceData* instance = GetCaplInstanceData(handle);
  if (nullptr == instance)
  {
    VServiceMap::iterator lSearchService(gServiceMap.find(handle));
    if (gServiceMap.end() != lSearchService)
    {
      VIACapl* service = lSearchService->second;
      try
      {
        instance = new CaplInstanceData(service);
      }
      catch (std::bad_alloc&)
      {
        return; // proceed without change
      }
      instance->GetCallbackFunctions();
      gCaplMap[handle] = instance;
    }
  }
}

void CAPLEXPORT CAPLPASCAL appEnd(uint32_t handle)
{
  CaplInstanceData* inst = GetCaplInstanceData(handle);
  if (inst == nullptr)
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

VIACLIENT(void) VIARegisterCDLL(VIACapl* service)
{
  uint32_t  handle;
  VIAResult result;

  if (service == nullptr)
  {
    return;
  }

  result = service->GetCaplHandle(&handle);
  if (result != kVIA_OK)
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
  VCaplMap::iterator lIter = gCaplMap.begin();
  const int32_t cNumberOfEntries = (int32_t)gCaplMap.size();
  int32_t i = 0;
  while (lIter != gCaplMap.end() && i < cNumberOfEntries)
  {
    appEnd((*lIter).first);
    lIter = gCaplMap.begin(); // first element should have vanished
    i++; // assure that no more erase trials take place than the original size of the map
  }

  // just for clarity (would be done automatically)
  gCaplMap.clear();
  gServiceMap.clear();
}
