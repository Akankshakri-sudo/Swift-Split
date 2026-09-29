#pragma once
#include <string>

bool encryptFile(const std::string& in,
                 const std::string& out,
                 const std::string& password);

bool decryptFile(const std::string& in,
                 const std::string& out,
                 const std::string& password);