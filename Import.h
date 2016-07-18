#pragma once
#include "stdafx.h"

class PeFile;

struct Import
{
    // Computed Fields

    DWORD64 FileAddress;
    const DWORD BlockSize = 20; // This only constitue the Import Directory Table

    string ModuleName;
    vector<string> ModuleFunctionNames;
    vector<int> ModuleOrdinalNumbers;

    // Fields in PE

    DWORD ImportModuleNameRVA;
    DWORD TimeStamp;
    DWORD ForwarderChain;         // TODO: not sure what it is
    DWORD ImportLookupTableRVA;
    DWORD ImportAddressTableRVA;  // TODO: not sure what it is

    UINT ReadImport(const PeFile& peFile, DWORD64 fileOffset);
    void DumpImport(const PeFile& peFile);

private:
    UINT ReadImportModuleName(const PeFile& peFile, DWORD64 fileOffset);
    UINT ReadImportModuleFunctions(const PeFile& peFile, DWORD64 fileOffset);
};
