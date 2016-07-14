#pragma once

#include "stdafx.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"


class PeFile {
    fstream in;
public:
    DosHeader DosHeader;
    CoffHeader CoffHeader;
    OptionalHeader OptHeader;
    vector<Section> Sections;
    //TODO: Implement move semantics in Section
    Section* LocateInSection(DWORD rva);
    DWORD PeFile::RvaToFa(DWORD Rva);
    // DWORD RvaToFa(DWORD rva);
    PeFile(string pefile);
    void ReadPeFile();
    void DumpPeFile();
};
