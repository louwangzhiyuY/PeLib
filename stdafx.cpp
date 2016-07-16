// stdafx.cpp : source file that includes just the standard includes
// PeLib.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"
// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

void Dump(vector<char>& bytes)
{
    int count = 0;
    for (auto &c : bytes) {
        printf("%02x ", c & 0xff);
        count++;
        if (count == 16) {
            cout << endl;
            count = 0;
        }
    }
}

UINT CopyFromFile(fstream& in, BYTE **buffer, BYTE *field, int nbytes)
{
    in.read((char *)*buffer, nbytes);
    if (!in)
        return PE_FILE_READ_ERROR;

    for (int i = 0; i < nbytes; i++)
        field[i] = (*buffer)[i] & 0xff;

    *buffer = *buffer + nbytes;

    return PE_SUCCESS;
}

void HexDump(BYTE *buf, size_t size)
{
	vector<BYTE> left;
	vector<BYTE> right;

	for (size_t i = 0; i < size; i++) {
		BYTE byte = buf[i] & 0xff;
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
