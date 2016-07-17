#pragma once
#include "stdafx.h"

class PeFile;

struct Import
{
    // Computed Fields

    DWORD64 FileAddress;
    const DWORD BlockSize = 20;

    string ModuleName;
    vector<string> ModuleFunctionNames;
    vector<int> ModuleOrdinalNumbers;

    // Fields in PE

    ULONG ImportModuleNameRVA;
    ULONG TimeStamp;
    ULONG ForwarderChain;         // TODO: not sure what it is
    ULONG ImportLookupTableRVA;
    ULONG ImportAddressTableRVA;  // TODO: not sure what it is

    UINT ReadImport(const PeFile& peFile, DWORD64 fileOffset);
    void DumpImport(const PeFile& peFile);

private:
    UINT ReadImportModuleName(const PeFile& peFile, DWORD64 fileOffset);
    UINT ReadImportModuleFunctions(const PeFile& peFile, DWORD64 fileOffset);
};
