#include "stdafx.h"
#include "Section.h"

Section::Section() : header{ 0 } {

}
void Section::ReadSection(fstream& in)
{
	ReadSectionHeader(in);
	ReadSectionBody(in);
}

void Section::ReadSectionHeader(fstream& in)
{
	char *ptr = (char *)header;

    copy_from_file(in, &ptr, (char *)&Name,                 sizeof(Name));
    copy_from_file(in, &ptr, (char *)&VirtualSize,                 sizeof(VirtualSize));
    copy_from_file(in, &ptr, (char *)&VirtualAddress,       sizeof(VirtualAddress));
    copy_from_file(in, &ptr, (char *)&SizeOfRawData,        sizeof(SizeOfRawData));
    copy_from_file(in, &ptr, (char *)&PointerToRawData,     sizeof(PointerToRawData));
    copy_from_file(in, &ptr, (char *)&PointerToRelocations, sizeof(PointerToRelocations));
    copy_from_file(in, &ptr, (char *)&PointerToLinenumbers, sizeof(PointerToLinenumbers));
    copy_from_file(in, &ptr, (char *)&NumberOfRelocations,  sizeof(NumberOfRelocations));
    copy_from_file(in, &ptr, (char *)&NumberOfLinenumbers,  sizeof(NumberOfLinenumbers));
    copy_from_file(in, &ptr, (char *)&Characteristics,      sizeof(Characteristics));

}

void Section::ReadSectionBody(fstream& in)
{
	long pos = in.tellp();
	in.seekp(PointerToRawData, ios_base::beg);
	for (DWORD i = 0; i < SizeOfRawData; i++) {
		char byte = 0;
		in.read(&byte, 1);
		body.push_back(byte & 0xff);
	}
	in.seekp(pos, ios_base::beg);
}

void Section::DumpSection()
{
	DumpSectionHeader();
	int yes;
	cout << "Dump " << Name << "?";
	cin >> yes;
	if (yes)
		DumpSectionBody();
}

void Section::DumpSectionHeader()
{
	//dump(vector<char>(header, header + SECTION_HEADER_SIZE));
	printf("    %-30s: %s\n", "Name", (char *)&Name);
    printf("    %-30s: %lx\n", "VirtualSize", VirtualSize);
    printf("    %-30s: %lx\n", "VirtualAddress", VirtualAddress);
    printf("    %-30s: %lx\n", "SizeOfRawData", SizeOfRawData);
    printf("    %-30s: %lx\n", "PointerToRawData", PointerToRawData);
    printf("    %-30s: %lx\n", "PointerToRelocations", PointerToRelocations);
    printf("    %-30s: %lx\n", "PointerToLinenumbers", PointerToLinenumbers);
    printf("    %-30s: %x\n", "NumberOfRelocations", NumberOfRelocations);
    printf("    %-30s: %x\n", "NumberOfLinenumbers", NumberOfLinenumbers);
    printf("    %-30s: %lx\n", "Characteristics", Characteristics);
}

void Section::DumpSectionBody()
{
	cout << "Dumping Section..." << endl;
	HexDump(body.data(), body.size());
}