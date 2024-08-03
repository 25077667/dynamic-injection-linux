#include <Ptrace.hpp>
#include <DynamicLinkingLinux.hpp>

#include <iostream>

#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>

namespace
{
    namespace detail
    {
        template <typename... Args>
        int ptrace_retry(__ptrace_request request, pid_t pid, Args... args)
        {
            constexpr auto MAX_RETRY = 5;
            for (int retryCount = 0; retryCount < MAX_RETRY; ++retryCount)
            {
                auto ret = ptrace(request, pid, args...);
                if (ret != -1)
                    return ret;

                // usleep for a while and retry, we give way to the target process
                usleep(1);
            }
            return -1;
        }
    }
}

ErrorCode mapErrnoToErrorCode()
{
    switch (errno)
    {
    case ESRCH:
        return ErrorCode::INVALID_PROCESS;
    case EFAULT:
        return ErrorCode::INVALID_MEMORY;
    case EACCES:
    case EPERM:
        return ErrorCode::INVALID_PERMISSION;
    case EINVAL:
        return ErrorCode::INVALID_ARGUMENT;
    default:
        return ErrorCode::INVALID_UNKNOWN;
    }
}

ErrorCode Ptrace::attach(pid_t pid) noexcept
{
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1)
    {
        return mapErrnoToErrorCode();
    }
    return ErrorCode::SUCCESS;
}

ErrorCode Ptrace::detach(pid_t pid) noexcept
{
    // need stop the process before detach
    kill(pid, SIGSTOP);
    waitpid(pid, nullptr, 0);

    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1)
    {
        return mapErrnoToErrorCode();
    }

    kill(pid, SIGCONT);
    return ErrorCode::SUCCESS;
}

std::optional<user_regs_struct> Ptrace::fetchRegs(pid_t pid) noexcept
{
    user_regs_struct regs;
    if (detail::ptrace_retry(PTRACE_GETREGS, pid, nullptr, &regs) == -1)
    {
        return std::nullopt;
    }
    return regs;
}

ErrorCode Ptrace::applyRegs(pid_t pid, const user_regs_struct &regs) noexcept
{
    if (detail::ptrace_retry(PTRACE_SETREGS, pid, nullptr, const_cast<user_regs_struct *>(&regs)) == -1)
    {
        return mapErrnoToErrorCode();
    }
    return ErrorCode::SUCCESS;
}

std::optional<std::vector<uint8_t>> Ptrace::read(pid_t pid, std::size_t addr, std::size_t len) noexcept
{
    std::vector<uint8_t> buffer(len);
    for (std::size_t i = 0; i < len; i += sizeof(long))
    {
        errno = 0;
        long word = detail::ptrace_retry(PTRACE_PEEKTEXT, pid, addr + i, nullptr);
        if (errno != 0)
        {
            return std::nullopt;
        }
        std::memcpy(buffer.data() + i, &word, sizeof(long));
    }
    return buffer;
}

ErrorCode Ptrace::write(pid_t pid, std::size_t addr, const std::vector<uint8_t> &data) noexcept
{
    for (std::size_t i = 0; i < data.size(); i += sizeof(long))
    {
        long word;
        std::memcpy(&word, data.data() + i, sizeof(long));
        if (detail::ptrace_retry(PTRACE_POKETEXT, pid, addr + i, word) == -1)
        {
            return mapErrnoToErrorCode();
        }
    }
    return ErrorCode::SUCCESS;
}

ErrorCode Ptrace::resume(pid_t pid) noexcept
{
    if (detail::ptrace_retry(PTRACE_CONT, pid, nullptr, nullptr) == -1)
    {
        return mapErrnoToErrorCode();
    }
    return ErrorCode::SUCCESS;
}

ErrorCode Ptrace::call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept
{
    auto backup_regs = fetchRegs(pid);
    if (!backup_regs.has_value())
    {
        return ErrorCode::INVALID_REGISTER;
    }

    user_regs_struct regs = *backup_regs;
    long args_values[6];
    for (int i = 0; i < 6; ++i)
    {
        args_values[i] = va_arg(args, long);
    }

#if defined(__x86_64__)
    regs.rip = oep_addr;
    regs.rbp = reinterpret_cast<uint64_t>(stack.base()) - 0x10;
    regs.rsp = reinterpret_cast<uint64_t>(stack.base()) - 0x20;
    regs.rdi = args_values[0];
    regs.rsi = args_values[1];
    regs.rdx = args_values[2];
    regs.rcx = args_values[3];
    regs.r8 = args_values[4];
    regs.r9 = args_values[5];
#else
    return ErrorCode::INVALID_SYSTEM;
#endif
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) != 0)
    {
        return mapErrnoToErrorCode();
    }

    // Kick the target process to execute the function
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0)
    {
        return mapErrnoToErrorCode();
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    {
        return ErrorCode::SUCCESS;
    }
    else if (WIFEXITED(status))
    {
        return ErrorCode::PROCESS_EXITED;
    }

    return ErrorCode::INVALID_INTERNAL;
}

ErrorCode Ptrace::call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept
{
    va_list args;
    va_start(args, stack);
    auto ret = call_oep(pid, oep_addr, stack, args);
    va_end(args);
    return ret;
}

ErrorCode Ptrace::patch_oep(pid_t pid, long oep_addr, const SnapShotData<SnapShotCategory::OEP> &data) noexcept
{
    std::vector<uint8_t> buffer(data.data.begin(), data.data.end());
    return write(pid, oep_addr, buffer);
}

ErrorCode Ptrace::remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept
{
    SnapShotData<SnapShotCategory::OEP> oep_patch;
    oep_patch.data = {0xff, 0xd0, 0xcc, 0xc3}; // call rax, int3, ret

    if (patch_oep(pid, call_addr, oep_patch) != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    // Call the OEP
    auto result = call_oep(pid, call_addr, stack, args);
    if (result != ErrorCode::SUCCESS)
    {
        return result;
    }

    auto new_regs = fetchRegs(pid);
    if (!new_regs.has_value())
    {
        return ErrorCode::INVALID_REGISTER;
    }
    return_value = new_regs->rax;

    return ErrorCode::SUCCESS;
}

ErrorCode Ptrace::remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept
{
    va_list args;
    va_start(args, stack);
    auto ret = remote_call(pid, call_addr, return_value, stack, args);
    va_end(args);
    return ret;
}

ErrorCode Ptrace::remote_syscall(pid_t pid, long syscall_num, long &return_value, ...) noexcept
{
    va_list args;
    va_start(args, return_value);
    auto ret = remote_syscall(pid, syscall_num, return_value, args);
    va_end(args);
    return ret;
}

ErrorCode Ptrace::remote_syscall(pid_t pid, long syscall_num, long &return_value, va_list args) noexcept
{
    // construct the oep with syscall:
    // 0x0f 0x05 : syscall
    SnapShotData<SnapShotCategory::OEP> oep_patch;
    oep_patch.data = {0x0f, 0x05, 0xcc, 0xc3}; // syscall, int3, ret

    if (patch_oep(pid, syscall_num, oep_patch) != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    // Call the OEP
    auto result = call_oep(pid, syscall_num, Foreign::MemoryBlock<Foreign::MemoryType::Stack>(), args);
    if (result != ErrorCode::SUCCESS)
    {
        return result;
    }

    auto new_regs = fetchRegs(pid);
    if (!new_regs.has_value())
    {
        return ErrorCode::INVALID_REGISTER;
    }
    return_value = new_regs->rax;

    return ErrorCode::SUCCESS;
}
