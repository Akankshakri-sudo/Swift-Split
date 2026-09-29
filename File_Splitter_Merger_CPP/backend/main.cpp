#include "splitter.h"
#include "crypto.h"

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>   // for remove()

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  split <file> <outDir> <parts>\n";
        cout << "  merge <part1> <part2> ... <output>\n";
        cout << "  encrypt <input> <output> <password>\n";
        cout << "  decrypt <input> <output> <password>\n";
        return 0;
    }

    string cmd = argv[1];

    /* ================= SPLIT ================= */
    if (cmd == "split") {
        if (argc < 5) {
            cout << "Usage: split <file> <outDir> <parts>\n";
            return 0;
        }

        string file = argv[2];
        string outDir = argv[3];
        int parts = stoi(argv[4]);

        char choice;
        cout << "Do you want to encrypt split files? (y/n): ";
        cin >> choice;

        string password;
        if (choice == 'y' || choice == 'Y') {
            cout << "Enter password: ";
            cin >> password;
        }

        // Split the file
        splitFile(file, outDir, parts);

        // Encrypt each part if chosen
        if (choice == 'y' || choice == 'Y') {
            string filename = file.substr(file.find_last_of("/\\") + 1);

for (int i = 1; i <= parts; i++) {

    string part = outDir + "/" + filename + "_part" + to_string(i);
    string enc  = part + ".enc";

    encryptFile(part, enc, password);
    remove(part.c_str());
}
        }

        cout << "Split completed successfully.\n";
    }

    /* ================= MERGE ================= */
    else if (cmd == "merge") {
        if (argc < 4) {
            cout << "Usage: merge <part1> <part2> ... <output>\n";
            return 0;
        }

        char choice;
        cout << "Are the files encrypted? (y/n): ";
        cin >> choice;

        string password;
        if (choice == 'y' || choice == 'Y') {
            cout << "Enter password: ";
            cin >> password;
        }

        vector<string> filesToMerge;
        vector<string> tempFiles;

        for (int i = 2; i < argc - 1; i++) {
            string file = argv[i];

            if (choice == 'y' || choice == 'Y') {
                string dec = file + ".dec";
                if (!decryptFile(file, dec, password)) {
    cout << "Decryption failed. Wrong password.\n";
    return 1;
}

tempFiles.push_back(dec);
            } else {
                tempFiles.push_back(file);
            }
        }

        mergeFiles(tempFiles, argv[argc - 1]);

        // Clean up temporary decrypted files
        if (choice == 'y' || choice == 'Y') {
            for (const auto& f : tempFiles) {
                remove(f.c_str());
            }
        }

        cout << "Merge completed successfully.\n";
    }

    /* ================= ENCRYPT ================= */
    else if (cmd == "encrypt") {
        if (argc != 5) {
            cout << "Usage: encrypt <input> <output> <password>\n";
            return 0;
        }

        encryptFile(argv[2], argv[3], argv[4]);
        cout << "Encryption completed.\n";
    }

    /* ================= DECRYPT ================= */
    else if (cmd == "decrypt") {
        if (argc != 5) {
            cout << "Usage: decrypt <input> <output> <password>\n";
            return 0;
        }

        decryptFile(argv[2], argv[3], argv[4]);
        cout << "Decryption completed.\n";
    }

    else {
        cout << "Unknown command.\n";
    }

    return 0;
}