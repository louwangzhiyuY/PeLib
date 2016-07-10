#pragma once
#include "stdafx.h"

#define COFF_HEADER_SIZE 24

class CoffHeader {
    BYTE header[COFF_HEADER_SIZE];
public:
    ULONG Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;

    CoffHeader();
    void ReadCoffHeader(fstream& in);
    void DumpCoffHeader();
};
