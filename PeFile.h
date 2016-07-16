#pragma once

#include "stdafx.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"


class PeFile {
public:
    //TODO: Implement move semantics in Section
    DWORD RvaToFa(DWORD rva);
    PeFile(string pefile);
    Section LocateInSection(DWORD rva);
    void DumpPeFile();
    void ReadPeFile();

private:
    CoffHeader ReadCoffHeader();
    DosHeader ReadDosHeader();
    OptionalHeader ReadOptionalHeader();
    Section ReadSection();
    void LocateAndReadDataDirectoryContents(const vector<Section>& sections);
    void ReadSectionContent(Section& section);
    void ReadSectionHeader(Section& section);

    CoffHeader      m_coffHeader;
    DosHeader       m_dosHeader;
    fstream         m_peStream;
    OptionalHeader  m_optHeader;
    vector<Section> m_sections;

};
