#include "stdafx.h"
#include "PeErrors.h"
#include "PECommon.h"

UINT CopyFromFile(fstream& in, char *field, int nbytes)
{
    in.read(field, nbytes);
    if (!in)
        return PE_FILE_READ_ERROR;

    return PE_SUCCESS;
}

UINT HexDump(string peFileName, DWORD64 fileOffset, size_t size)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFileName, fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    in.seekg(fileOffset, ios_base::beg);

    vector<BYTE> left;
    vector<BYTE> right;

    for (size_t i = 0; i < size; i++) {
        char buf = 0;
        in.read(&buf, 1);   // TODO: Add a check here
        BYTE byte = buf & 0xff;
        left.push_back(byte);
        right.push_back(!iscntrl(byte) ? byte : '.');
        if (left.size() == 16 || i == size - 1) {
            printf("%016I64x| ", i - left.size() + 1);
            for (auto &b : left)
                printf("%02x ", b);
            cout << string(3 * (16 - left.size()), ' ') << "| ";
            for (auto &b : right)
                printf("%c", b);
            cout << string(16 - left.size(), ' ') << endl;

            left.clear();
            right.clear();
        }
    }

    return ret;
}

string ValueToDescription(const vector<ValueDescription>& valueDescriptions, DWORD value, BOOLEAN bitwiseFlag)
{
    string description;
    stringstream hexValuePrefix;
    hexValuePrefix << hex << value << " -> ";

    description += hexValuePrefix.str();

    if (bitwiseFlag) {
        for (auto &vd : valueDescriptions) {
            if (vd.Value & value) {
                description += vd.Description;
                description += "|";
            }
        }
        return description;
    }
    else {
        auto iter = find_if(valueDescriptions.begin(), valueDescriptions.end(), [&value](ValueDescription vd) {
            return vd.Value == value;
        });
        if (iter != valueDescriptions.end())
            description += iter->Description;
        return description;
    }
}
