#ifndef __SCC_DLL_FILE_MAPPING_HPP__
#define __SCC_DLL_FILE_MAPPING_HPP__
#pragma once

#include <string>
#include <cstddef>
#include <cstdint>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

class FileMapping
{
public:
    FileMapping(const std::string &file_path);
    FileMapping(const std::string &file_path, int permission); // O_... permission flags
    ~FileMapping();

    bool isValid() const;
    void *getBase() const;
    std::size_t getSize() const;

private:
    void *base_;
    std::size_t size_;
    int fd_;
};

#endif // FILE_MAPPING_HPP