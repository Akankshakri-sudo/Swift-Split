#include "crypto.h"
#include <openssl/evp.h>
#include <fstream>
#include <vector>

using namespace std;

static bool process(bool enc,
                    const string& in,
                    const string& out,
                    const string& pass)
{
    unsigned char key[32], iv[16];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(),
                   nullptr,
                   (unsigned char*)pass.data(),
                   pass.size(), 1, key, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, enc);

    ifstream fin(in, ios::binary);
    ofstream fout(out, ios::binary);

    vector<unsigned char> inbuf(4096), outbuf(4096 + 16);
    int outlen;

    while (fin.good()) {
        fin.read((char*)inbuf.data(), inbuf.size());
        int r = fin.gcount();
        EVP_CipherUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), r);
        fout.write((char*)outbuf.data(), outlen);
    }

    if (!EVP_CipherFinal(ctx, outbuf.data(), &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;   // wrong password
}

fout.write((char*)outbuf.data(), outlen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool encryptFile(const string& in,
                 const string& out,
                 const string& password)
{
    return process(true, in, out, password);
}

bool decryptFile(const string& in,
                 const string& out,
                 const string& password)
{
    return process(false, in, out, password);
}