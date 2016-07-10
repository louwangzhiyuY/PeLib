#include "stdafx.h"
#include "CoffHeader.h"

CoffHeader::CoffHeader() : header{ 0 } {

}

void CoffHeader::ReadCoffHeader(fstream& in)
{
    char *ptr = (char *)header;

    copy_from_file(in, &ptr, (char *)&Signature,            sizeof(Signature));
    copy_from_file(in, &ptr, (char *)&Machine,              sizeof(Machine));
    copy_from_file(in, &ptr, (char *)&NumberOfSections,     sizeof(NumberOfSections));
    copy_from_file(in, &ptr, (char *)&TimeDateStamp,        sizeof(TimeDateStamp));
    copy_from_file(in, &ptr, (char *)&PointerToSymbolTable, sizeof(PointerToSymbolTable));
    copy_from_file(in, &ptr, (char *)&NumberOfSymbols,      sizeof(NumberOfSymbols));
    copy_from_file(in, &ptr, (char *)&SizeOfOptionalHeader, sizeof(SizeOfOptionalHeader));
    copy_from_file(in, &ptr, (char *)&Characteristics,      sizeof(Characteristics));
}

void CoffHeader::DumpCoffHeader()
{
    //dump(vector<char>(header, header + COFF_HEADER_SIZE));
    cout << "Dumping Coff Header" << endl;
    printf("    %-25s: %c%c\n", "Signature",    ((char *)&Signature)[0], ((char *)&Signature)[1]);
    printf("    %-25s: %x\n", "Machine",                 Machine);
    printf("    %-25s: %x\n", "NumberOfSections",        NumberOfSections);
    printf("    %-25s: %lx\n", "TimeDateStamp",           TimeDateStamp);
    printf("    %-25s: %lx\n", "PointerToSymbolTable",    PointerToSymbolTable);
    printf("    %-25s: %lx\n", "NumberOfSymbols",         NumberOfSymbols);
    printf("    %-25s: %x\n", "SizeOfOptionalHeader",    SizeOfOptionalHeader);
    printf("    %-25s: %x\n", "Characteristics",         Characteristics);
}