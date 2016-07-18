#include "stdafx.h"
#include "CoffHeader.h"
#include "PeCommon.h"
#include "PeErrors.h"
#include "PeFile.h"

vector<ValueDescription> MachineFlags = {
    {0x0, "IMAGE_FILE_MACHINE_UNKNOWN"},
    {0x14c, "IMAGE_FILE_MACHINE_I386"},
    {0x166, "IMAGE_FILE_MACHINE_R4000"},
    {0x169, "IMAGE_FILE_MACHINE_WCEMIPSV2"},
    {0x1a2, "IMAGE_FILE_MACHINE_SH3"},
    {0x1a3, "IMAGE_FILE_MACHINE_SH3DSP"},
    {0x1a6, "IMAGE_FILE_MACHINE_SH4"},
    {0x1a8, "IMAGE_FILE_MACHINE_SH5"},
    {0x1c0, "IMAGE_FILE_MACHINE_ARM"},
    {0x1c2, "IMAGE_FILE_MACHINE_THUMB"},
    {0x1c4, "IMAGE_FILE_MACHINE_ARMNT"},
    {0x1d3, "IMAGE_FILE_MACHINE_AM33"},
    {0x1f0, "IMAGE_FILE_MACHINE_POWERPC"},
    {0x1f1, "IMAGE_FILE_MACHINE_POWERPCFP"},
    {0x200, "IMAGE_FILE_MACHINE_IA64"},
    {0x266, "IMAGE_FILE_MACHINE_MIPS16"},
    {0x366, "IMAGE_FILE_MACHINE_MIPSFPU"},
    {0x466, "IMAGE_FILE_MACHINE_MIPSFPU16"},
    {0xebc, "IMAGE_FILE_MACHINE_EBC"},
    {0x5032, "IMAGE_FILE_MACHINE_RISCV32"},
    {0x5064, "IMAGE_FILE_MACHINE_RISCV64"},
    {0x5128, "IMAGE_FILE_MACHINE_RISCV128"},
    {0x8664, "IMAGE_FILE_MACHINE_AMD64"},
    {0x9041, "IMAGE_FILE_MACHINE_M32R"},
};

vector<ValueDescription> CharacteristicsFlags = {
    {0x0001, "IMAGE_FILE_RELOCS_STRIPPED"},
    {0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"},
    {0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"},
    {0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"},
    {0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"},
    {0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"},
    {0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"},
    {0x0100, "IMAGE_FILE_32BIT_MACHINE"},
    {0x0200, "IMAGE_FILE_DEBUG_STRIPPED"},
    {0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"},
    {0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"},
    {0x1000, "IMAGE_FILE_SYSTEM"},
    {0x2000, "IMAGE_FILE_DLL"},
    {0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"},
    {0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"},
};

UINT CoffHeader::ReadCoffHeader(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    // Store the file address of COFF Header
    FileAddress = fileOffset;

    // Move file pointer to PE header
    in.seekg(FileAddress, ios_base::beg);

    COPY_AND_CHECK_RETURN_STATUS(in, Signature);
    if (((char *)&Signature)[0] != 'P' &&
        ((char *)&Signature)[1] != 'E')
        return PE_NOT_VALID_PE;

    COPY_AND_CHECK_RETURN_STATUS(in, Machine);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfSections);
    COPY_AND_CHECK_RETURN_STATUS(in, TimeDateStamp);
    COPY_AND_CHECK_RETURN_STATUS(in, PointerToSymbolTable);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfSymbols);
    COPY_AND_CHECK_RETURN_STATUS(in, SizeOfOptionalHeader);
    COPY_AND_CHECK_RETURN_STATUS(in, Characteristics);

    return ret;
}

void CoffHeader::DumpCoffHeader(const PeFile& /* peFile */)
{
    cout << "Dumping Coff Header" << endl;
    printf("    %-25s: %c%c\n", "Signature",            ((char *)&Signature)[0], ((char *)&Signature)[1]);
    printf("    %-25s: %s\n",   "Machine",              ValueToDescription(MachineFlags, Machine, FALSE).c_str());
    printf("    %-25s: %x\n",   "NumberOfSections",     NumberOfSections);
    printf("    %-25s: %lx\n",  "TimeDateStamp",        TimeDateStamp);
    printf("    %-25s: %lx\n",  "PointerToSymbolTable", PointerToSymbolTable);
    printf("    %-25s: %lx\n",  "NumberOfSymbols",      NumberOfSymbols);
    printf("    %-25s: %x\n",   "SizeOfOptionalHeader", SizeOfOptionalHeader);
    printf("    %-25s: %s\n",   "Characteristics",      ValueToDescription(CharacteristicsFlags, Characteristics, TRUE).c_str());
}
