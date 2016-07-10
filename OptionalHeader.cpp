#include "stdafx.h"
#include "OptionalHeader.h"

OptionalHeader::OptionalHeader() : header{ 0 } {

}

void OptionalHeader::ReadOptionalHeader(fstream& in)
{
    char *ptr = header;

    copy_from_file(in, &ptr, (char *)&Magic,                       sizeof(Magic));
    copy_from_file(in, &ptr, (char *)&MajorLinkerVersion,          sizeof(MajorLinkerVersion));
    copy_from_file(in, &ptr, (char *)&MinorLinkerVersion,          sizeof(MinorLinkerVersion));
    copy_from_file(in, &ptr, (char *)&SizeOfCode,                  sizeof(SizeOfCode));
    copy_from_file(in, &ptr, (char *)&SizeOfInitializedData,       sizeof(SizeOfInitializedData));
    copy_from_file(in, &ptr, (char *)&SizeOfUninitializedData,     sizeof(SizeOfUninitializedData));
    copy_from_file(in, &ptr, (char *)&AddressOfEntryPoint,         sizeof(AddressOfEntryPoint));
    copy_from_file(in, &ptr, (char *)&BaseOfCode,                  sizeof(BaseOfCode));

    if (Magic == 0x10b) // PE32
        copy_from_file(in, &ptr, (char *)&BaseOfData, sizeof(BaseOfData));

    copy_from_file(in, &ptr, (char *)&ImageBase,                   Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (char *)&SectionAlignment,            sizeof(SectionAlignment));
    copy_from_file(in, &ptr, (char *)&FileAlignment,               sizeof(FileAlignment));
    copy_from_file(in, &ptr, (char *)&MajorOperatingSystemVersion, sizeof(MajorOperatingSystemVersion));
    copy_from_file(in, &ptr, (char *)&MinorOperatingSystemVersion, sizeof(MinorOperatingSystemVersion));
    copy_from_file(in, &ptr, (char *)&MajorImageVersion,           sizeof(MajorImageVersion));
    copy_from_file(in, &ptr, (char *)&MinorImageVersion,           sizeof(MinorImageVersion));
    copy_from_file(in, &ptr, (char *)&MajorSubsystemVersion,       sizeof(MajorSubsystemVersion));
    copy_from_file(in, &ptr, (char *)&MinorSubsystemVersion,       sizeof(MinorSubsystemVersion));
    copy_from_file(in, &ptr, (char *)&Win32VersionValue,           sizeof(Win32VersionValue));
    copy_from_file(in, &ptr, (char *)&SizeOfImage,                 sizeof(SizeOfImage));
    copy_from_file(in, &ptr, (char *)&SizeOfHeaders,               sizeof(SizeOfHeaders));
    copy_from_file(in, &ptr, (char *)&CheckSum,                    sizeof(CheckSum));
    copy_from_file(in, &ptr, (char *)&Subsystem,                   sizeof(Subsystem));
    copy_from_file(in, &ptr, (char *)&DllCharacteristics,          sizeof(DllCharacteristics));
    copy_from_file(in, &ptr, (char *)&SizeOfStackReserve,          Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (char *)&SizeOfStackCommit,           Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (char *)&SizeOfHeapReserve,           Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (char *)&SizeOfHeapCommit,            Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (char *)&LoaderFlags,                 sizeof(LoaderFlags));
    copy_from_file(in, &ptr, (char *)&NumberOfRvaAndSizes,         sizeof(NumberOfRvaAndSizes));

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
	for (DWORD i = 0; i < min(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
        copy_from_file(in, &ptr, (char *)&DataDirectory[i],   sizeof(DataDirectoryEntry));

    headerSize = ptr - header;
}

void OptionalHeader::DumpOptionalHeader()
{
    //dump(vector<char>(header, header + headerSize));
    cout << "Dumping Optional Header" << endl;
    printf("    %-30s: %x\n", "Magic",                   Magic);
    printf("    %-30s: %x\n", "MajorLinkerVersion",      MajorLinkerVersion);
    printf("    %-30s: %x\n", "MinorLinkerVersion",      MinorLinkerVersion);
    printf("    %-30s: %lx\n", "SizeOfCode",              SizeOfCode);
    printf("    %-30s: %lx\n", "SizeOfInitializedData",   SizeOfInitializedData);
    printf("    %-30s: %lx\n", "SizeOfUninitializedData", SizeOfUninitializedData);
    printf("    %-30s: %lx\n", "AddressOfEntryPoint",     AddressOfEntryPoint);
    printf("    %-30s: %lx\n", "BaseOfCode",              BaseOfCode);

    if (Magic == 0x10b) // PE32
        printf("    %-30s: %lx\n", "BaseOfData",              BaseOfData);

    printf("    %-30s: %llx\n", "ImageBase",                   ImageBase);
    printf("    %-30s: %lx\n",   "SectionAlignment",            SectionAlignment);
    printf("    %-30s: %lx\n",   "FileAlignment",               FileAlignment);
    printf("    %-30s: %x\n",   "MajorOperatingSystemVersion", MajorOperatingSystemVersion);
    printf("    %-30s: %x\n",   "MinorOperatingSystemVersion", MinorOperatingSystemVersion);
    printf("    %-30s: %x\n",   "MajorImageVersion",           MajorImageVersion);
    printf("    %-30s: %x\n",   "MinorImageVersion",           MinorImageVersion);
    printf("    %-30s: %x\n",   "MajorSubsystemVersion",       MajorSubsystemVersion);
    printf("    %-30s: %x\n",   "MinorSubsystemVersion",       MinorSubsystemVersion);
    printf("    %-30s: %lx\n",   "Win32VersionValue",           Win32VersionValue);
    printf("    %-30s: %lx\n",   "SizeOfImage",                 SizeOfImage);
    printf("    %-30s: %lx\n",   "SizeOfHeaders",               SizeOfHeaders);
    printf("    %-30s: %lx\n",   "CheckSum",                    CheckSum);
    printf("    %-30s: %x\n",   "Subsystem",                   Subsystem);
    printf("    %-30s: %x\n",   "DllCharacteristics",          DllCharacteristics);
    printf("    %-30s: %llx\n", "SizeOfStackReserve",          SizeOfStackReserve);
    printf("    %-30s: %llx\n", "SizeOfStackCommit",           SizeOfStackCommit);
    printf("    %-30s: %llx\n", "SizeOfHeapReserve",           SizeOfHeapReserve);
    printf("    %-30s: %llx\n", "SizeOfHeapCommit",            SizeOfHeapCommit);
    printf("    %-30s: %lx\n",   "LoaderFlags",                 LoaderFlags);
    printf("    %-30s: %lx\n",   "NumberOfRvaAndSizes",         NumberOfRvaAndSizes);

	printf("    Data Directories\n");
	for (DWORD i = 0; i < min(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
		printf("        Data Directory[%2d]: %-6s: %-10lx %-15s: %lx\n", i, "Size", DataDirectory[i].Size, "Virutal Address", DataDirectory[i].VirtualAddress);
}
