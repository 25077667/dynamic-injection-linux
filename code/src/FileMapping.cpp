#include <FileMapping.hpp>

#include <iostream>

FileMapping::FileMapping(const std::string &file_path)
    : base_(MAP_FAILED), size_(0), fd_(-1)
{
    fd_ = open(file_path.c_str(), O_RDONLY);
    if (fd_ < 0)
    {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return;
    }

    struct stat st;
    if (fstat(fd_, &st) < 0)
    {
        std::cerr << "Failed to get file size: " << file_path << std::endl;
        close(fd_);
        return;
    }

    size_ = st.st_size;
    base_ = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (base_ == MAP_FAILED)
    {
        std::cerr << "Failed to map file: " << file_path << std::endl;
        close(fd_);
    }
}

FileMapping::FileMapping(const std::string &file_path, int permission)
    : base_(MAP_FAILED), size_(0), fd_(-1)
{
    fd_ = open(file_path.c_str(), permission);
    if (fd_ < 0)
    {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return;
    }

    struct stat st;
    if (fstat(fd_, &st) < 0)
    {
        std::cerr << "Failed to get file size: " << file_path << std::endl;
        close(fd_);
        return;
    }

    size_ = st.st_size;
    base_ = mmap(nullptr, size_, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd_, 0);
    if (base_ == MAP_FAILED)
    {
        std::cerr << "Failed to map file: " << file_path << std::endl;
        close(fd_);
    }
}

FileMapping::~FileMapping()
{
    if (base_ != MAP_FAILED)
    {
        munmap(base_, size_);
    }
    if (fd_ >= 0)
    {
        close(fd_);
    }
}

bool FileMapping::isValid() const
{
    return base_ != MAP_FAILED;
}

void *FileMapping::getBase() const
{
    return base_;
}

std::size_t FileMapping::getSize() const
{
    return size_;
}
