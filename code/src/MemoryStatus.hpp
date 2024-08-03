#ifndef __SCC_DLL_MEMORYSTATUS_HPP__
#define __SCC_DLL_MEMORYSTATUS_HPP__
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace MemoryStatus
{
    // VmFlags enum class and related functions
    enum class VmFlags
    {
        RD,
        WR,
        EX,
        SH,
        MR,
        MW,
        ME,
        MS,
        GD,
        PF,
        DW,
        LO,
        IO,
        SR,
        RR,
        DC,
        DE,
        AC,
        NR,
        HT,
        AR,
        DD,
        SD,
        MM,
        HG,
        NH,
        MG,
    };

    /**
     * Converts a vector of MemoryStats::VmFlags to a string representation.
     *
     * @param flags The vector of MemoryStats::VmFlags to convert.
     * @return A string representation of the flags.
     */
    std::string vmFlagsToString(const std::vector<VmFlags> &flags) noexcept;

    /**
     * Converts a string representation of virtual memory flags to a vector of MemoryStats::VmFlags.
     *
     * @param vmFlagsStr The string representation of virtual memory flags.
     * @return A vector of MemoryStats::VmFlags representing the converted flags.
     * @note Empty if the string is empty or contains invalid flags.
     */
    std::vector<VmFlags> stringToVmFlags(const std::string &vmFlagsStr) noexcept;

    struct Map
    {
        uint64_t start;
        uint64_t end;
        struct Device
        {
            uint32_t major;
            uint32_t minor;
        } device;

        uint32_t inode;
        std::string name;
    };
    // PageSize struct
    struct PageSize
    {
        int kernel; // Kernel page size in kilobytes
        int mmu;    // MMU page size in kilobytes

        PageSize(int kernel = 0, int mmu = 0)
            : kernel(kernel), mmu(mmu) {}
    };

    // Pss struct
    struct Pss
    {
        int total; // Proportional Set Size in kilobytes
        int dirty; // Dirty PSS in kilobytes

        Pss(int total = 0, int dirty = 0)
            : total(total), dirty(dirty) {}
    };

    // MemoryUsage struct
    struct MemoryUsage
    {
        int shared_clean;
        int shared_dirty;
        int private_clean;
        int private_dirty;

        MemoryUsage(int shared_clean = 0, int shared_dirty = 0, int private_clean = 0, int private_dirty = 0)
            : shared_clean(shared_clean), shared_dirty(shared_dirty), private_clean(private_clean), private_dirty(private_dirty) {}
    };

    // AdvancedMemory struct
    struct AdvancedMemory
    {
        int anonymous;
        int ksm;
        int lazy_free;
        int anon_huge_pages;
        int shmem_pmd_mapped;
        int shared_hugetlb;
        int private_hugetlb;

        AdvancedMemory(int anonymous = 0, int ksm = 0, int lazy_free = 0, int anon_huge_pages = 0,
                       int shmem_pmd_mapped = 0, int shared_hugetlb = 0, int private_hugetlb = 0)
            : anonymous(anonymous), ksm(ksm), lazy_free(lazy_free), anon_huge_pages(anon_huge_pages),
              shmem_pmd_mapped(shmem_pmd_mapped), shared_hugetlb(shared_hugetlb), private_hugetlb(private_hugetlb) {}
    };

    // Swap struct
    struct Swap
    {
        int total; // Total swap in kilobytes
        int pss;   // Swap PSS in kilobytes

        Swap(int total = 0, int pss = 0)
            : total(total), pss(pss) {}
    };
    class SmapBuilder;
    class Smap
    {
    public:
        // Getters for read-only access
        Map getMap() const { return map; }
        uint32_t getSize() const { return size; }
        uint32_t getRss() const { return rss; }
        uint32_t getReferenced() const { return referenced; }
        PageSize getPageSize() const { return page_size; }
        Pss getPss() const { return pss; }
        MemoryUsage getMemoryUsage() const { return memory_usage; }
        AdvancedMemory getAdvancedMemory() const { return advanced_memory; }
        Swap getSwap() const { return swap; }
        uint32_t getLocked() const { return locked; }
        bool getThpEligible() const { return thp_eligible; }
        std::vector<VmFlags> getVmFlags() const { return vm_flags; }

    private:
        friend class SmapBuilder; // Only SmapBuilder can construct and modify

        // Member variables (not constant)
        Map map;
        uint32_t size;
        uint32_t rss;
        uint32_t referenced;
        PageSize page_size;
        Pss pss;
        MemoryUsage memory_usage;
        AdvancedMemory advanced_memory;
        Swap swap;
        uint32_t locked;
        bool thp_eligible;
        std::vector<VmFlags> vm_flags;

        // Private constructor
        Smap() = default;
    };

    class SmapBuilder
    {
    public:
        SmapBuilder &setMap(const Map &map)
        {
            smap_.map = map;
            return *this;
        }

        SmapBuilder &setSize(uint32_t size)
        {
            smap_.size = size;
            return *this;
        }

        SmapBuilder &setRss(uint32_t rss)
        {
            smap_.rss = rss;
            return *this;
        }

        SmapBuilder &setReferenced(uint32_t referenced)
        {
            smap_.referenced = referenced;
            return *this;
        }

        SmapBuilder &setPageSize(const PageSize &page_size)
        {
            smap_.page_size = page_size;
            return *this;
        }

        SmapBuilder &setPss(const Pss &pss)
        {
            smap_.pss = pss;
            return *this;
        }

        SmapBuilder &setMemoryUsage(const MemoryUsage &memory_usage)
        {
            smap_.memory_usage = memory_usage;
            return *this;
        }

        SmapBuilder &setAdvancedMemory(const AdvancedMemory &advanced_memory)
        {
            smap_.advanced_memory = advanced_memory;
            return *this;
        }

        SmapBuilder &setSwap(const Swap &swap)
        {
            smap_.swap = swap;
            return *this;
        }

        SmapBuilder &setLocked(uint32_t locked)
        {
            smap_.locked = locked;
            return *this;
        }

        SmapBuilder &setThpEligible(bool thp_eligible)
        {
            smap_.thp_eligible = thp_eligible;
            return *this;
        }

        SmapBuilder &setVmFlags(const std::vector<VmFlags> &vm_flags)
        {
            smap_.vm_flags = vm_flags;
            return *this;
        }

        Smap build() const
        {
            return smap_;
        }

        Smap exchange(Smap &smap) noexcept
        {
            auto tmp = smap_;
            smap_ = smap;
            return tmp;
        }

    private:
        Smap smap_;
    };
} // namespace MemoryStatus

#endif // __SCC_DLL_MEMORYSTATUS_HPP__
