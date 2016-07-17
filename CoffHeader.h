#pragma once
#include "stdafx.h"

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

    void DumpCoffHeader(string peFileName);
};
