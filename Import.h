#pragma once
#include "stdafx.h"


struct Import
{
    // Computed Fields

    DWORD64 FileAddress;
    string ModuleName;
    vector<string> ModuleFunctionNames;
    vector<int> ModuleOrdinalNumbers;

    // Fields in PE

    ULONG ImportModuleNameRVA;
    ULONG TimeStamp;
    ULONG ForwarderChain;         // TODO: not sure what it is
    ULONG ImportLookupTableRVA;
    ULONG ImportAddressTableRVA;  // TODO: not sure what it is

    void DumpImport(string peFileName);
};
