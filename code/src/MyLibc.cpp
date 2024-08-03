#include <MyLibc.hpp>
#include <FileMapping.hpp>

#include <sstream>
#include <fstream>
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <cstdint>
#include <vector>
#include <limits>
#include <iostream>

#include <sys/stat.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>

static constexpr std::array POSSIBLE_LIBC_PREFIXES = {
    "/libc-",      // glibc
    "/libc.so.6",  // glibc
    "/ld-musl-",   // musl libc
    "/libc.so",    // bionic libc
    "/ld-linux-",  // another common prefix for glibc
    "/ld-2.",      // another common prefix for glibc
    "/ld-uClibc-", // uClibc
    "/libc.2"      // glibc
};

namespace
{
    namespace detail
    {
        bool is_libc_file(const std::string &path) noexcept;

        template <typename Ehdr, typename Shdr, typename Sym>
        bool buildLibcFunctionsTableImpl(void *base, std::unordered_map<std::string, uint64_t> &libc_functions_);

        template <typename Ehdr, typename Shdr, typename Sym>
        uint64_t readLibcBaseOffsetImpl(void *base);

        template <typename Ehdr, typename Shdr>
        uint64_t findSection(const void *base, const std::string &section_name);
    }
}

MyLibc::MyLibc(const std::string &target_process_maps)
{
    libc_path_ = getLibcPath(target_process_maps);
    reloadLibcFunctions(libc_path_);
}

std::string MyLibc::getLibcPath(const std::string &target_process_maps) const noexcept
{
    if (!this->libc_path_.empty())
    {
        return this->libc_path_;
    }

    std::ifstream maps(target_process_maps);
    if (!maps.is_open())
    {
        return "";
    }

    std::string line;
    while (std::getline(maps, line))
    {

        std::istringstream iss(line);
        std::string addr_range;
        std::string perms;
        std::string offset;
        std::string dev;
        std::string inode;
        std::string pathname;

        iss >> addr_range >> perms >> offset >> dev >> inode >> pathname;
        // is libc file and permission contains 'x'
        if (detail::is_libc_file(pathname) && perms.find('x') != std::string::npos)
        {
            return pathname;
        }
    }

    return "";
}

uint64_t MyLibc::getLibcFunctionOffset(const std::string &function_name) const noexcept
{
    auto it = libc_functions_.find(function_name);
    if (it == libc_functions_.end())
    {
        return 0;
    }

    return it->second;
}

bool MyLibc::reloadLibcFunctions(const std::string &libc_path) noexcept
{
    if (libc_path.empty())
    {
        return false;
    }

    this->libc_path_ = libc_path;
    this->libc_base_offset_ = getLibcBaseOffset(libc_path_);
    return buildLibcFunctionsTable(libc_path);
}

uint64_t MyLibc::getLibcBaseOffset(const std::string &libc_path) noexcept
{
    if (this->libc_base_offset_)
    {
        return this->libc_base_offset_;
    }

    FileMapping fileMapping(libc_path);
    if (!fileMapping.isValid())
    {
        return false;
    }

    auto *base = fileMapping.getBase();
    auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
        std::cerr << "Not a valid ELF file: " << libc_path << std::endl;
        return false;
    }

    uint64_t base_offset = 0;
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
    {
        base_offset = detail::readLibcBaseOffsetImpl<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(base);
    }
    else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
    {
        base_offset = detail::readLibcBaseOffsetImpl<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(base);
    }
    else
    {
        std::cerr << "Unsupported ELF class: " << static_cast<int>(ehdr->e_ident[EI_CLASS]) << std::endl;
    }

    this->libc_base_offset_ = base_offset;
    return base_offset;
}

uint64_t MyLibc::getLibcBeginInMemory(const std::string &target_process_maps) noexcept
{
    // parse the /proc/pid/maps file to get the base address of libc
    std::ifstream maps(target_process_maps);
    if (!maps.is_open())
    {
        return 0;
    }

    std::string line;
    while (std::getline(maps, line))
    {
        std::istringstream iss(line);
        std::string addr_range;
        std::string perms;
        std::string offset;
        std::string dev;
        std::string inode;
        std::string pathname;

        iss >> addr_range >> perms >> offset >> dev >> inode >> pathname;
        if (pathname == libc_path_)
        {
            auto dash_pos = addr_range.find('-');
            if (dash_pos == std::string::npos)
            {
                return 0;
            }

            std::string begin = addr_range.substr(0, dash_pos);
            return std::stoull(begin, nullptr, 16);
        }
    }

    return 0;
}

bool MyLibc::buildLibcFunctionsTable(const std::string &libc_path) noexcept
{
    if (libc_path.empty())
    {
        return false;
    }

    libc_functions_.clear();

    FileMapping fileMapping(libc_path);
    if (!fileMapping.isValid())
    {
        return false;
    }

    auto *base = fileMapping.getBase();
    auto *ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
        std::cerr << "Not a valid ELF file: " << libc_path << std::endl;
        return false;
    }

    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
    {
        return detail::buildLibcFunctionsTableImpl<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(base, libc_functions_);
    }
    else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
    {
        return detail::buildLibcFunctionsTableImpl<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(base, libc_functions_);
    }
    else
    {
        std::cerr << "Unsupported ELF class: " << static_cast<int>(ehdr->e_ident[EI_CLASS]) << std::endl;
        return false;
    }

    // unreachable
    __builtin_unreachable();
    return false;
}

bool detail::is_libc_file(const std::string &path) noexcept
{
    // Check if the path contains one of the possible prefixes
    if (std::none_of(POSSIBLE_LIBC_PREFIXES.begin(), POSSIBLE_LIBC_PREFIXES.end(),
                     [&path](const std::string &prefix)
                     { return path.find(prefix) != std::string::npos; }))
    {
        return false;
    }

    // Check if the file is readable and executable
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
    {
        return false;
    }

    if ((st.st_mode & S_IRUSR) == 0 || (st.st_mode & S_IXUSR) == 0)
    {
        return false;
    }

    // Check if the file is an ELF file
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    char elf_magic[4];
    if (!file.read(elf_magic, 4))
    {
        return false;
    }

    return memcmp(elf_magic, ELFMAG, 4) == 0;
}

template <typename Ehdr, typename Shdr, typename Sym>
bool detail::buildLibcFunctionsTableImpl(void *base, std::unordered_map<std::string, uint64_t> &libc_functions_)
{
    auto *ehdr = reinterpret_cast<Ehdr *>(base);

    uint64_t dynsym_offset = findSection<Ehdr, Shdr>(base, ".dynsym");
    if (dynsym_offset == 0)
    {
        std::cerr << "Failed to find .dynsym section" << std::endl;
        return false;
    }

    uint64_t dynstr_offset = findSection<Ehdr, Shdr>(base, ".dynstr");
    if (dynstr_offset == 0)
    {
        std::cerr << "Failed to find .dynstr section" << std::endl;
        return false;
    }

    auto *symtab = reinterpret_cast<Sym *>(reinterpret_cast<uint8_t *>(base) + dynsym_offset);
    auto *shdr = reinterpret_cast<Shdr *>(reinterpret_cast<uint8_t *>(base) + ehdr->e_shoff);
    size_t symcount = 0;

    for (int i = 0; i < ehdr->e_shnum; ++i)
    {
        if (reinterpret_cast<const char *>(reinterpret_cast<const uint8_t *>(base) + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name) == std::string(".dynsym"))
        {
            symcount = shdr[i].sh_size / sizeof(Sym);
            break;
        }
    }

    auto *strtab = reinterpret_cast<const char *>(reinterpret_cast<uint8_t *>(base) + dynstr_offset);

    for (std::size_t i = 0; i < symcount; i++)
    {
        const char *func_name = &strtab[symtab[i].st_name];
        if (func_name[0] != '\0')
        { // Skip empty names
            uint64_t offset = symtab[i].st_value;
            libc_functions_.emplace(func_name, offset);
        }
    }

    return true;
}

template <typename Ehdr, typename Shdr, typename Sym>
uint64_t detail::readLibcBaseOffsetImpl(void *base)
{
    auto section_offset = findSection<Ehdr, Shdr>(base, ".text");
    if (section_offset == 0)
    {
        std::cerr << "Failed to find .text section" << std::endl;
        return 0;
    }

    auto *symtab = reinterpret_cast<const Sym *>(reinterpret_cast<const uint8_t *>(base) + section_offset);
    return symtab->st_value;
}

template <typename Ehdr, typename Shdr>
uint64_t detail::findSection(const void *base, const std::string &section_name)
{
    auto *ehdr = reinterpret_cast<const Ehdr *>(base);
    auto *shdr = reinterpret_cast<const Shdr *>(reinterpret_cast<const uint8_t *>(base) + ehdr->e_shoff);
    const char *section_names = nullptr;

    if (ehdr->e_shstrndx != SHN_UNDEF && ehdr->e_shstrndx < ehdr->e_shnum)
    {
        section_names = reinterpret_cast<const char *>(reinterpret_cast<const uint8_t *>(base) + shdr[ehdr->e_shstrndx].sh_offset);

        for (int i = 0; i < ehdr->e_shnum; i++)
        {
            const auto &current_section_name = std::string(section_names + shdr[i].sh_name);
            if (current_section_name == section_name)
            {
                return shdr[i].sh_offset;
            }
        }
    }
    else
    {
        std::cerr << "Invalid section name string table index: " << ehdr->e_shstrndx << std::endl;
    }

    return 0;
}
