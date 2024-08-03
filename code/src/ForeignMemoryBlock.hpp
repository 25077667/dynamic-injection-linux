#ifndef __SCC_DLL_FOREIGN_HPP__
#define __SCC_DLL_FOREIGN_HPP__
#pragma once

#include <cstdint>

namespace Foreign
{
    enum class MemoryType
    {
        Stack,
        // Heap, not implemented yet
        Text,
    };

    template <MemoryType>
    struct MemoryBlock
    {
    };

    /**
     * @brief This stack will be allocated in the remote process.
     * Highly recommended the size should align with N * page_size;
     */
    template <>
    struct MemoryBlock<MemoryType::Stack>
    {
        MemoryBlock() = default;
        MemoryBlock(void *base, uint32_t size) : base_(base), size_(size) {}
        MemoryBlock(void *base) : base_(base) {}

        void *base() const { return base_; }
        uint32_t size() const { return size_; }

    private:
        void *base_ = nullptr;        // The highest address of the stack.
        uint32_t size_ = 8192 * 1024; // 8MB, just like the main thread's stack
    };

    // stack memory layout:
    // |&&&&&&&&&&&&&&&&&&&| <- The kernel space
    // |                   |
    // |                   |
    // |-------------------| <- base()
    // |                   |
    // | our  ForeignStack |
    // |                   |
    // |-------------------| <- base() - size()
    // |                   |
    // |                   |
    // |       ...         |

    template <>
    struct MemoryBlock<MemoryType::Text>
    {
        MemoryBlock() = default;
        MemoryBlock(void *base, uint32_t size) : base_(base), size_(size) {}

        void *base() const { return base_; }
        uint32_t size() const { return size_; }

    private:
        void *base_ = nullptr; // The highest address of the text.
        uint32_t size_ = 0;
    };
}

#endif // __SCC_DLL_FOREIGN_HPP__