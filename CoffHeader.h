#pragma once
#include "stdafx.h"

class PeFile;

struct CoffHeader
{
    // Computed Fields

    DWORD64 FileAddress;
    const DWORD BlockSize = 24;

    // Fields in PE

    ULONG Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;

    UINT ReadCoffHeader(const PeFile& peFile, DWORD64 fileOffset);
    void DumpCoffHeader(const PeFile& peFile);
};
