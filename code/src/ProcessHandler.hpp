#ifndef __SCC_DLL_PROCESS_HANDLER_HPP__
#define __SCC_DLL_PROCESS_HANDLER_HPP__
#pragma once
#include <DynamicLinkingLinux.hpp>
#include <MemoryStatus.hpp>
#include <ThreadAttr.hpp>
#include <MyLibc.hpp>
#include <SnapShotData.hpp>
#include <ForeignMemoryBlock.hpp>

#include <string>
#include <cstddef>
#include <cstdint>
#include <array>

class ProcessHandlerTest;

/**
 * @class ProcessHandler
 * Handles interaction with a process identified by a PID. This includes attaching to and detaching from
 * the process, memory management, and thread handling within the target process context.
 */
class ProcessHandler
{
    friend class ProcessHandlerTest;
    friend class DynamicLinkingLinux;

protected:
    using pid_t = long; // Represents the process identifier type.

    pid_t pid_ = 0;         // PID of the target process.
    bool attached_ = false; // Flag indicating whether the handler is currently attached to the process.
    MyLibc target_libc_;    // Wrapper for the system libc.

    SnapShotData<SnapShotCategory::OEP> oep_data_;
    SnapShotData<SnapShotCategory::Register> register_data_;
    Foreign::MemoryBlock<Foreign::MemoryType::Stack> foreign_stack_ = {};

    std::string target_exe_;
    uint64_t target_libc_begin_ = 0;
    uint64_t inode_ = 0;
    uint64_t oep_addr = 0;
    long injected_dl = 0;

public:
    /**
     * Constructs a ProcessHandler for a specific process by its PID.
     * @param pid The process identifier.
     * @throws std::runtime_error If the process cannot be attached.
     */
    explicit ProcessHandler(pid_t pid);

#ifdef UNIT_TEST
    ProcessHandler(pid_t pid, MyLibc target_libc) : pid_(pid), target_libc_(target_libc) {}
#endif

    /**
     * Destructor. Automatically detaches from the process if currently attached.
     */
    ~ProcessHandler();

    /**
     * Attempts to attach to the process. Thread-safe, reentrant-safe.
     * @return ErrorCode indicating the result of the attach operation.
     */
    ErrorCode attach() noexcept;

    /**
     * Detaches from the process. Thread-safe, reentrant-safe.
     * @return ErrorCode indicating the result of the detach operation.
     */
    ErrorCode detach() noexcept;

    /**
     * Takes a snapshot of the specified category of data in the remote process.
     * @param data The snapshot data object to be filled.
     * @param do_save_cache Whether to save the snapshot data in the cache.
     * @return ErrorCode indicating the result of the snapshot operation.
     */
    template <SnapShotCategory category>
    ErrorCode SnapShot(SnapShotData<category> &data, bool do_save_cache = true) noexcept;

    /**
     * Takes a snapshot of all data in the remote process.
     * @return ErrorCode indicating the result of the snapshot operation.
     */
    ErrorCode SnapShotAll() noexcept;

    /**
     * Restores the specified category of data in the remote process.
     * @param data The snapshot data object to be restored.
     * @return ErrorCode indicating the result of the restore operation.
     */
    ErrorCode Restore() noexcept;

    /**
     * Restores the specified category of data in the remote process.
     * @param data The snapshot data object to be restored.
     * @return ErrorCode indicating the result of the restore operation.
     */
    template <SnapShotCategory category>
    ErrorCode Restore(const SnapShotData<category> &data) noexcept;

    /**
     * @brief Finds the entry point of a function in the remote process.
     * @param function_signature The signature of the function to be found.
     * @param remote_addr The address of the function entry point in the remote process.
     * @return ErrorCode indicating the result of the function entry point search operation.
     */
    ErrorCode FindEntry(const std::string &function_signature, long &remote_addr) noexcept;

    /**
     * @brief Injects code into the remote process.
     * @param so_file_path The path to the shared object file to be injected.
     * @return ErrorCode indicating the result of the code injection operation.
     * @note The remote process will use dlopen to load the shared object file, and store the handle on the injected_dl.
     */
    ErrorCode InjectCode(const std::string &so_file_path) noexcept;

    /**
     * Starts a new thread in the remote process.
     * @param fn_ptr The address of the function to be executed in the new thread.
     * @return ErrorCode indicating the result of the thread start operation.
     */
    ErrorCode start_thread(long fn_ptr) noexcept;

protected:
    std::string get_target_exe(bool reload = false) noexcept;
    uint64_t get_inode_number(bool reload = false) noexcept;
    uint64_t get_oep_address(bool reload = false) noexcept;
    std::string get_maps() const noexcept;

    std::string get_exe_path(int pid) const noexcept
    {
        return std::string("/proc/") + std::to_string(pid) + "/exe";
    }

    std::string get_maps_path(int pid) const noexcept
    {
        return std::string("/proc/") + std::to_string(pid) + "/maps";
    }

    std::string get_mem_path(int pid) const noexcept
    {
        return std::string("/proc/") + std::to_string(pid) + "/mem";
    }

    std::string resolve_realpath(const std::string &path) const noexcept;
    uint64_t fetch_inode_number(const std::string &path) const noexcept;
    uint64_t fetch_oep_address(const std::string &path) const noexcept;
    uint64_t find_target_map_base(uint64_t inode_number) const noexcept;
    long alloc(uint32_t size, int PROT, int flags) noexcept;

    /**
     * Allocates memory in the remote process.
     * @param block The memory block object to be filled.
     * @param size The size of the memory block to be allocated.
     * @return ErrorCode indicating the result of the memory allocation operation.
     */
    ErrorCode Acquire(Foreign::MemoryBlock<Foreign::MemoryType::Stack> &block, uint32_t size) noexcept;
    ErrorCode set_stack() noexcept;
};

#endif // __SCC_DLL_PROCESS_HANDLER_HPP__