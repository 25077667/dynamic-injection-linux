namespace Ptrace {
    ErrorCode attach(pid_t pid) noexcept;
    ErrorCode detach(pid_t pid) noexcept;
    std::optional<user_regs_struct> fetchRegs(pid_t pid) noexcept;
    ErrorCode applyRegs(pid_t pid, const user_regs_struct &regs) noexcept;
    std::optional<std::vector<uint8_t>> read(pid_t pid, std::size_t addr, std::size_t len) noexcept;
    ErrorCode write(pid_t pid, std::size_t addr, const std::vector<uint8_t> &data) noexcept;
    ErrorCode resume(pid_t pid) noexcept;
    ErrorCode call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept;
    ErrorCode call_oep(pid_t pid, long oep_addr, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept;
    ErrorCode patch_oep(pid_t pid, long oep_addr, const SnapShotData<SnapShotCategory::OEP> &data) noexcept;
    ErrorCode remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, va_list args) noexcept;
    ErrorCode remote_call(pid_t pid, long call_addr, long &return_value, const Foreign::MemoryBlock<Foreign::MemoryType::Stack> &stack, ...) noexcept;
    ErrorCode remote_syscall(pid_t pid, long syscall_num, long &return_value, ...) noexcept;
    ErrorCode remote_syscall(pid_t pid, long syscall_num, long &return_value, va_list args) noexcept;
}
