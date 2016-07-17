#include "stdafx.h"
#include "PeErrors.h"
#include "PeFile.h"

int main()
{
    UINT ret = PE_SUCCESS;
    //PeFile pe("C:\\Users\\vineelko\\Downloads\\SysinternalsSuite\\accesschk.exe");
    //PeFile pe("C:\\Users\\Vineel\\Documents\\Visual Studio 2015\\Projects\\VCTemp\\Debug\\VCTemp.exe");
    PeFile pe("C:\\Windows\\System32\\ntoskrnl.exe");
    ret = pe.ReadPeFile();
    if (!ret)
        pe.DumpPeFile();
    else
        cout << "Reading pe file failed..." << ret << endl;
    return ret;
}
