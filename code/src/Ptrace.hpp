#ifndef __SCC_DLL_PTRACE_HPP__
#define __SCC_DLL_PTRACE_HPP__
#pragma once
#include <DynamicLinkingLinux.hpp>
#include <SnapShotData.hpp>
#include <ForeignMemoryBlock.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include <string>

#include <sys/user.h> // user_regs_struct
#include <cstdarg>

namespace Ptrace
{
    ErrorCode attach(pid_t pid) noexcept;
    ErrorCode detach(pid_t pid) noexcept;
    std::optional<user_regs_struct> fetchRegs(pid_t pid) noexcept;
    ErrorCode applyRegs(pid_t pid, const user_regs_struct &regs) noexcept;
    std::optional<std::vector<uint8_t>> read(pid_t pid, std::size_t addr, std::size_t len) noexcept;
    ErrorCode write(pid_t pid, std::size_t addr, const std::vector<uint8_t> &data) noexcept;
    ErrorCode resume(pid_t pid) noexcept;

    /**
     * @brief Call oep function in the target process.
     *
     * @note: This function would help you to call some functions in the target process with the following requirements:
     *        1. The function should be in the target process, with valid address with executable permission.
     *        2. You should invoke the `patch_oep` first to jump to the function indirectly.
     * example:
     * ```
     * // patch the oep to jump to the function
     * SnapShotData<SnapShotCategory::OEP> data;
     * data.data = {
     *      0xff, 0xd0  // call rax
     *      0xcc,       // int3, we use int3 to notify our tracer the function is called
     *      0xc3,       // ret, dummy ... you also could use some "junk code" to obfuscate the behavior
     * }; // about 64 bytes
     * patch_oep(pid, oep_addr, data);
     * // call the function
     * call_oep(pid, oep_addr, stack_higher_base, args);
     *
     * // You should restore all
     * ErrorCode res = process_handler->Restore();
     * ```
     */
    ErrorCode call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept;

    // call_oep (... version)
    ErrorCode call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept;

    /**
     * @brief Patch the original entry point to jump to the function.
     *
     * @note: This function would help you to patch the original entry point to jump to the function with the following requirements:
     *        1. The function should be in the target process, with valid address with executable permission.
     *        2. Please refer to the `call_oep` function to see how to use it.
     */
    ErrorCode patch_oep(pid_t pid, long oep_addr, const SnapShotData<SnapShotCategory::OEP> &data) noexcept;

    /**
     * @brief Calls the original entry point function in the target process after patching the original entry point.
     *
     * This function combines the functionality of the `patch_oep` and `call_oep` functions.
     *
     * @param pid The process ID of the target process.
     * @param call_addr The address of the function to call.
     * @param return_value The variable to store the return value of the function.
     * @param stack The stack memory block to use for the function call.
     * @param args The arguments to pass to the function.
     * @return An ErrorCode indicating the success or failure of the operation.
     */
    ErrorCode remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept;

    /**
     * @brief Calls the original entry point function in the target process after patching the original entry point.
     *
     * This function combines the functionality of the `patch_oep` and `call_oep` functions.
     *
     * @param pid The process ID of the target process.
     * @param call_addr The address of the function to call.
     * @param return_value The variable to store the return value of the function.
     * @param stack The stack memory block to use for the function call.
     * @param ... The arguments to pass to the function.
     * @return An ErrorCode indicating the success or failure of the operation.
     */
    ErrorCode remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept;

    ErrorCode remote_syscall(pid_t pid, long syscall_num, long &return_value, ...) noexcept;
    ErrorCode remote_syscall(pid_t pid, long syscall_num, long &return_value, va_list args) noexcept;
}

#endif // __SCC_DLL_PTRACE_HPP__