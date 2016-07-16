#include "stdafx.h"
#include "PeFile.h"

int main()
{
    PeFile pe("C:\\Users\\vineelko\\Downloads\\SysinternalsSuite\\accesschk.exe");
    //PeFile pe("c:\\users\\vineel\\documents\\visual studio 2015\\projects\\vctemp\\x64\\debug\\vctemp.exe");
    pe.ReadPeFile();
    pe.DumpPeFile();

    return 0;
}
