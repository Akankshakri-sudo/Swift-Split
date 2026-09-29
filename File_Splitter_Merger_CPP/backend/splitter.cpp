#include "splitter.h"
#include <fstream>
#include <vector>
#include <iostream>

using namespace std;

void splitFile(const string& file,
               const string& outDir,
               int parts)
{
    ifstream fin(file, ios::binary);
    if (!fin) {
        cout << "Error opening file\n";
        return;
    }

    fin.seekg(0, ios::end);
    long size = fin.tellg();
    fin.seekg(0);

    long baseSize = size / parts;
    long remainder = size % parts;

    vector<char> buffer(4096);

    for (int i = 0; i < parts; i++) {

        string filename = file.substr(file.find_last_of("/\\") + 1);

ofstream fout(outDir + "/" + filename + "_part" + to_string(i + 1), ios::binary);

        long currentPartSize = baseSize + (i < remainder ? 1 : 0);

        long remaining = currentPartSize;

        while (remaining > 0) {
            long chunkSize = min((long)buffer.size(), remaining);

            fin.read(buffer.data(), chunkSize);
            long bytesRead = fin.gcount();

            if (bytesRead <= 0) break;

            fout.write(buffer.data(), bytesRead);
            remaining -= bytesRead;
        }
    }
}


void mergeFiles(const vector<string>& files,
                const string& output)
{
    ofstream fout(output, ios::binary);
    vector<char> buffer(4096);

    for (const auto& f : files) {
        ifstream fin(f, ios::binary);
        while (fin.read(buffer.data(), buffer.size())) {
            fout.write(buffer.data(), fin.gcount());
        }
        fout.write(buffer.data(), fin.gcount());
    }
}