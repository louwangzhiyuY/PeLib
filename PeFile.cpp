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


