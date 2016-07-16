#include "stdafx.h"
#include "Import.h"

void Import::DumpImport(string /* peFileName */)
{
    cout << "Import Module Name: " << ModuleName << endl;
    printf("    %-25s: %lx\n", "NameRVA",               ImportModuleNameRVA);
    printf("    %-25s: %lx\n", "TimeStamp",             TimeStamp);
    printf("    %-25s: %lx\n", "ForwarderChain",        ForwarderChain);
    printf("    %-25s: %lx\n", "ImportLookupTableRVA",  ImportLookupTableRVA);
    printf("    %-25s: %lx\n", "ImportAddressTableRVA", ImportAddressTableRVA);

    if (ModuleFunctionNames.size() > 0) {
        printf("    %-25s:\n", "Module Function Names");
        for (auto& string : ModuleFunctionNames)
            cout << "        " << string << endl;
    }

    if (ModuleOrdinalNumbers.size() > 0) {
        printf("    %-25s:\n", "Module Ordinals");
        for (auto& ordinal : ModuleOrdinalNumbers)
            cout << "        " << ordinal << endl;
    }
}