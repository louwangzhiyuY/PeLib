#pragma once
#include "stdafx.h"

#define COFF_HEADER_SIZE 24

struct CoffHeader
{
    // Computed Fields

    DWORD64 FileAddress;

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
