#pragma once

#include "stdafx.h"
#include "PECommon.h"
#include "DosHeader.h"
#include "CoffHeader.h"
#include "OptionalHeader.h"
#include "Section.h"
#include "Import.h"
#include "Export.h"

class PeFile
{
public:
    explicit PeFile(string peFileName);
    DWORD RvaToFa(DWORD rva) const;
    void DumpPeFile();
    UINT ReadPeFile();
    const string& GetPeFilePath() const;
    bool IsPe32() const;
    DataDirectoryEntry GetDataDirectories(DataDirectoryType type) const;
private:
    UINT ReadSections();
    UINT ReadImports();
    Section LocateInSection(DWORD rva) const;

    string          m_peFileName;
    DosHeader       m_dosHeader;
    CoffHeader      m_coffHeader;
    OptionalHeader  m_optionalHeader;
    vector<Section> m_sections;
    vector<Import>  m_imports;
    Export          m_exports;
};
