#pragma once
#include "stdafx.h"

#define COFF_HEADER_SIZE 24

struct CoffHeader {
    BYTE header[COFF_HEADER_SIZE];


    ULONG Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;

    void DumpCoffHeader();
};
