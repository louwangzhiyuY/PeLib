#include "stdafx.h"
#include "PeFile.h"

int main()
{
    UINT ret = PE_SUCCESS;
    //PeFile pe("C:\\Users\\vineelko\\Downloads\\SysinternalsSuite\\accesschk.exe");
    PeFile pe("c:\\users\\vineel\\documents\\visual studio 2015\\projects\\vctemp\\x64\\debug\\vctemp.pdb");
    ret = pe.ReadPeFile();
    if (!ret)
        pe.DumpPeFile();
    else
        cout << "Reading pe file failed..." << ret << endl;
    return ret;
}
