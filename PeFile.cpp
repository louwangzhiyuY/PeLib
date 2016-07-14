// pe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PeFile.h"

PeFile::PeFile(string pefile) : in(pefile, fstream::binary | fstream::in | fstream::out) {
}

void PeFile::ReadPeFile() {
    DosHeader.ReadDosHeader(in);
    in.seekg(DosHeader.e_lfanew, ios_base::beg);
    CoffHeader.ReadCoffHeader(in);
    OptHeader.ReadOptionalHeader(in);
    for (int i = 0; i < CoffHeader.NumberOfSections; i++) {
        Section *section = new Section();
        section->ReadSection(in);
        Sections.push_back(*section);
    }
    // Read data directory content from their respective sections
    OptHeader.LocateAndReadDataDirectoryContents(in, Sections);
}

void PeFile::DumpPeFile() {

    DosHeader.DumpDosHeader();
    CoffHeader.DumpCoffHeader();
    OptHeader.DumpOptionalHeader();

    for (auto& secHeader : Sections) {
        secHeader.DumpSection();
        cout << endl << "===================" << endl;
    }
}

Section* PeFile::LocateInSection(DWORD Rva)
{
    for (auto& section : Sections)
        if (Rva >= section.VirtualAddress &&
            Rva <= section.VirtualAddress + section.VirtualSize)
            // file address = file offset of section   + (offset of  within section)
            return &section;
 
    return nullptr;
}

DWORD PeFile::RvaToFa(DWORD Rva)
{
    Section *section = LocateInSection(Rva);
    if (section)
        return section->PointerToRawData + (Rva - section->VirtualAddress);

    return 0;
}
