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
		SectionHeader *header = new SectionHeader();
		header->ReadSectionHeader(in);
		SecHeaders.push_back(*header);
	}
}

void PeFile::DumpPeFile() {

    DosHeader.DumpDosHeader();
    CoffHeader.DumpCoffHeader();
    OptHeader.DumpOptionalHeader();

	for (auto& secHeader : SecHeaders) {
		secHeader.DumpSectionHeader();
		cout << endl << "===================" << endl;
	}
}


