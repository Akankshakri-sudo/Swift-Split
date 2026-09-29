#pragma once
#include <string>
#include <vector>

void splitFile(const std::string& file,
               const std::string& outDir,
               int parts);

void mergeFiles(const std::vector<std::string>& files,
                const std::string& output);
