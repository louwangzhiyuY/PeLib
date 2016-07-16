#pragma once

#include "stdafx.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"

class PeFile
{
public:
    //TODO: Implement move semantics in Section
    DWORD RvaToFa(DWORD rva);
    PeFile(string pefile);
    Section LocateInSection(DWORD rva);
    void DumpPeFile();
    void ReadPeFile();

private:
    void ReadDosHeader();
    void ReadCoffHeader();
    void ReadOptionalHeader();
    void ReadSection(Section& section);
    void LocateAndReadDataDirectoryContents(const vector<Section>& sections);
    void ReadSectionContent(Section& section);
    void ReadSectionHeader(Section& section);

    fstream         m_peStream;
    DosHeader       m_dosHeader;
    CoffHeader      m_coffHeader;
    OptionalHeader  m_optionalHeader;
    vector<Section> m_sections;
};
