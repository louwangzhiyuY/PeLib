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

    PeFile(string pefile);
    void ReadPeFile();
    void DumpPeFile();
};
