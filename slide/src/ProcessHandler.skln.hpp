class ProcessHandler
{
protected:
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
    explicit ProcessHandler(pid_t pid);
    ~ProcessHandler();
    ErrorCode attach() noexcept;
    ErrorCode detach() noexcept;
    template <SnapShotCategory category>
    ErrorCode SnapShot(SnapShotData<category> &data, bool do_save_cache = true) noexcept;
    ErrorCode SnapShotAll() noexcept;
    ErrorCode Restore() noexcept;
    template <SnapShotCategory category>
    ErrorCode Restore(const SnapShotData<category> &data) noexcept;
    ErrorCode FindEntry(const std::string &function_signature, long &remote_addr) noexcept;
    ErrorCode InjectCode(const std::string &so_file_path) noexcept;
    ErrorCode start_thread(long fn_ptr) noexcept;
};
