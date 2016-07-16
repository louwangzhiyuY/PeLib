#pragma once

#include "stdafx.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"
#include "Import.h"

class PeFile
{
public:
    //TODO: Implement move semantics in Section
    DWORD RvaToFa(DWORD rva);
    PeFile(string pefile);
    Section LocateInSection(DWORD rva);
    UINT ReadImportModuleName(Import* import);
    UINT ReadImportModuleFunctions(Import* import);
    void DumpPeFile();
    UINT ReadPeFile();

private:
    UINT ReadDosHeader();
    UINT ReadCoffHeader();
    UINT ReadOptionalHeader();
    UINT ReadSection(Section& section);
    UINT DataDirectoryEntryRvaToFa(const vector<Section>& sections);
    UINT ReadImports(DWORD importDirectoryTableFA);

    fstream         m_peStream;
    string          m_peFileName;
    DosHeader       m_dosHeader;
    CoffHeader      m_coffHeader;
    OptionalHeader  m_optionalHeader;
    vector<Section> m_sections;
    vector<Import>  m_imports;
};
