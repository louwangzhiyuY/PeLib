#pragma once

#include "stdafx.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"


class PeFile {
    string fileName;
    fstream in;
    OptionalHeader ReadOptionalHeader();
    void LocateAndReadDataDirectoryContents(const vector<Section>& sections);
    CoffHeader ReadCoffHeader();
    DosHeader ReadDosHeader();
    Section ReadSection();
    void ReadSectionHeader(Section& sec);
    void ReadSectionContent(Section& sec);
public:
    DosHeader dosHeader;
    CoffHeader coffHeader;
    OptionalHeader optHeader;
    vector<Section> sections;
    //TODO: Implement move semantics in Section
    Section LocateInSection(DWORD rva);
    DWORD PeFile::RvaToFa(DWORD Rva);
    // DWORD RvaToFa(DWORD rva);
    PeFile(string pefile);
    void ReadPeFile();
    void DumpPeFile();
};
