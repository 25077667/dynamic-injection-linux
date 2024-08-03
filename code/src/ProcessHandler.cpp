#include <ProcessHandler.hpp>
#include <Ptrace.hpp>
#include <FileMapping.hpp>
#include <utilities.hpp>

#include <RemoteLoader.hpp>

#include <iostream>
#include <sstream>
#include <cstring>
#include <memory>
#include <fstream>

#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define DEBUG_MESSAGE(str)                                              \
    do                                                                  \
    {                                                                   \
        std::cerr << "[" << __FUNCTION__ << "]"                         \
                  << "(" << __LINE__ << ")" << " " << str << std::endl; \
    } while (0)

ProcessHandler::ProcessHandler(pid_t pid) : pid_(pid),
                                            attached_(false),
                                            target_libc_([](int pid)
                                                         { return std::string("/proc/") + std::to_string(pid) + "/maps"; }(pid))
{
    attach();
}

ProcessHandler::~ProcessHandler()
{
    detach();
}

ErrorCode ProcessHandler::attach() noexcept
{
    if (attached_)
    {
        return ErrorCode::SUCCESS;
    }

    ErrorCode err = Ptrace::attach(pid_);
    attached_ = (err == ErrorCode::SUCCESS);

    if (!attached_)
    {
        std::cerr << "Failed to attach to process: " << pid_ << " error message: " << strerror(errno)
                  << std::endl;
    }

    return err;
}

ErrorCode ProcessHandler::detach() noexcept
{
    if (!attached_)
    {
        return ErrorCode::SUCCESS;
    }

    ErrorCode err = Ptrace::detach(pid_);
    attached_ = !(err == ErrorCode::SUCCESS);

    if (attached_)
    {
        std::cerr << "Failed to detach from process: " << pid_ << " error message: " << strerror(errno)
                  << " error code: " << static_cast<int>(err)
                  << std::endl;
    }

    return err;
}

template <>
ErrorCode ProcessHandler::SnapShot<SnapShotCategory::OEP>(SnapShotData<SnapShotCategory::OEP> &data, bool do_save_cache) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    uint64_t oep_addr = get_oep_address();
    if (oep_addr == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    uint64_t inode_number = get_inode_number();
    if (inode_number == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    uint64_t target_map_base = find_target_map_base(inode_number);
    if (target_map_base == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    const auto &real_addr = target_map_base + oep_addr;

    int mem_fd = ::open(get_mem_path(pid_).c_str(), O_RDONLY);
    if (mem_fd == -1)
    {
        return ErrorCode::INVALID_PERMISSION;
    }

    auto close_mem_fd = [&mem_fd]()
    {
        if (mem_fd != -1)
        {
            ::close(mem_fd);
            mem_fd = -1;
        }
    };
    defer<decltype(close_mem_fd)> mem_fd_ptr(close_mem_fd);

    if (::lseek(mem_fd, real_addr, SEEK_SET) == -1)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    ssize_t bytes_read = ::read(mem_fd, &data, sizeof(data));
    if (bytes_read != sizeof(SnapShotData<SnapShotCategory::OEP>))
    {
        return ErrorCode::INVALID_IO;
    }

    if (do_save_cache)
    {
        oep_data_ = data;
    }

    return ErrorCode::SUCCESS;
}

template <>
ErrorCode ProcessHandler::SnapShot<SnapShotCategory::Register>(SnapShotData<SnapShotCategory::Register> &data, bool do_save_cache) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    auto regs = Ptrace::fetchRegs(pid_);
    if (!regs.has_value())
    {
        DEBUG_MESSAGE("Failed to fetch registers: " << strerror(errno));
        return ErrorCode::INVALID_MEMORY;
    }

    data.data = *regs;

    if (do_save_cache)
    {
        register_data_ = data;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode ProcessHandler::SnapShotAll() noexcept
{
    ErrorCode err = ErrorCode::SUCCESS;
    err = SnapShot<SnapShotCategory::OEP>(oep_data_);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    err = SnapShot<SnapShotCategory::Register>(register_data_);
    return err;
}

template <>
ErrorCode ProcessHandler::Restore<SnapShotCategory::OEP>(const SnapShotData<SnapShotCategory::OEP> &data) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    uint64_t oep_addr = get_oep_address();
    if (oep_addr == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    uint64_t inode_number = get_inode_number();
    if (inode_number == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    uint64_t target_map_base = find_target_map_base(inode_number);
    if (target_map_base == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    const auto &real_addr = target_map_base + oep_addr;

    int mem_fd = ::open(get_mem_path(pid_).c_str(), O_WRONLY);
    if (mem_fd == -1)
    {
        return ErrorCode::INVALID_PERMISSION;
    }

    auto close_mem_fd = [&mem_fd]()
    {
        if (mem_fd != -1)
        {
            ::close(mem_fd);
            mem_fd = -1;
        }
    };
    defer<decltype(close_mem_fd)> mem_fd_ptr(close_mem_fd);

    if (::lseek(mem_fd, real_addr, SEEK_SET) == -1)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    ssize_t bytes_written = ::write(mem_fd, &data.data, sizeof(data.data));
    if (bytes_written != sizeof(SnapShotData<SnapShotCategory::OEP>))
    {
        return ErrorCode::INVALID_IO;
    }

    return ErrorCode::SUCCESS;
}

template <>
ErrorCode ProcessHandler::Restore<SnapShotCategory::Register>(const SnapShotData<SnapShotCategory::Register> &data) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    return Ptrace::applyRegs(pid_, data.data);
}

ErrorCode ProcessHandler::Restore() noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    ErrorCode err = ErrorCode::SUCCESS;
    err = Restore<SnapShotCategory::OEP>(oep_data_);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    err = Restore<SnapShotCategory::Register>(register_data_);
    return err;
}

// FindEntry
ErrorCode ProcessHandler::FindEntry(const std::string &function_signature, long &remote_addr) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    if (function_signature.empty())
    {
        return ErrorCode::INVALID_ARGUMENT;
    }

    if (this->injected_dl == 0)
    {
        return ErrorCode::INVALID_OPERATION;
    }

    auto dlsym_addr = target_libc_.getLibcBeginInMemory(get_maps()) +
                      target_libc_.getLibcFunctionOffset("dlsym");
    if (dlsym_addr == 0)
    {
        return ErrorCode::INVALID_INTERNAL;
    }

    // backup the registers
    this->SnapShotAll();
    defer([this]()
          { this->Restore(); });

    if (set_stack() != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    // construct a dlsym remote call
    // remote_call
    long ret = 0;
    auto err = Ptrace::remote_call(pid_, dlsym_addr, ret, this->foreign_stack_, this->injected_dl, function_signature.c_str());
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    remote_addr = ret;
    return ErrorCode::SUCCESS;
}

ErrorCode ProcessHandler::Acquire(Foreign::MemoryBlock<Foreign::MemoryType::Stack> &block, uint32_t size) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    // backup the registers
    auto backup_regs = Ptrace::fetchRegs(pid_);
    if (!backup_regs.has_value())
    {
        return ErrorCode::INVALID_REGISTER;
    }
    defer([this, &backup_regs]()
          { Ptrace::applyRegs(pid_, *backup_regs); });

    // allocate the memory for remote process
    long stack_base = alloc(size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN);
    if (stack_base == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    block = Foreign::MemoryBlock<Foreign::MemoryType::Stack>(reinterpret_cast<void *>(stack_base), size);

    // restore the registers
    return Ptrace::applyRegs(pid_, *backup_regs);
}

ErrorCode ProcessHandler::InjectCode(const std::string &so_file_path) noexcept
{
    if (access(so_file_path.c_str(), F_OK) == -1)
    {
        return ErrorCode::INVALID_INJECTION;
    }

    this->SnapShotAll();
    defer([this]()
          { this->Restore(); });

    // Allocate memory for the RemoteLoader and arguments
    uint32_t loader_memory_size = loaderSize + sizeof(RemoteLoaderArgs) + so_file_path.size() + 1;
    long remote_memory_base = alloc(loader_memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    if (remote_memory_base == 0)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    // Write the RemoteLoader to the remote process
    std::vector<uint8_t> shellcode(loader_memory_size);
    memcpy(shellcode.data(), reinterpret_cast<void *>(&RemoteLoader), loaderSize);
    if (Ptrace::write(pid_, remote_memory_base, shellcode) != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_CODE;
    }

    // Write the arguments to the remote process
    auto dlopen_addr = target_libc_.getLibcBeginInMemory(get_maps()) +
                       target_libc_.getLibcFunctionOffset("dlopen");
    if (dlopen_addr == 0)
    {
        return ErrorCode::INVALID_INTERNAL;
    }
    std::vector<uint8_t> loader_args(sizeof(RemoteLoaderArgs) + so_file_path.size() + 1);
    RemoteLoaderArgs *args = reinterpret_cast<RemoteLoaderArgs *>(loader_args.data());
    args->dlopenAddr = reinterpret_cast<void *>(dlopen_addr);
    args->dlFlags = RTLD_LAZY;
    std::strncpy(args->filePath, so_file_path.c_str(), so_file_path.size());
    args->filePath[so_file_path.size()] = '\0'; // double check null-terminated
    if (Ptrace::write(pid_, remote_memory_base + loaderSize, loader_args) != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_CODE;
    }

    // Change the memory permission to PROT_READ | PROT_EXEC
    constexpr auto NR_mprotect = 125;
    long mprotect_ret = 0;
    ErrorCode err = Ptrace::remote_syscall(pid_, NR_mprotect, mprotect_ret, remote_memory_base, loader_memory_size, PROT_READ | PROT_EXEC);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    // Call the RemoteLoader
    SnapShotData<SnapShotCategory::OEP> oep;
    oep.data = {0xff, 0xd0, 0xcc, 0xc3};
    err = Ptrace::patch_oep(pid_, oep_addr, oep);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }
    err = set_stack();
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }
    err = Ptrace::call_oep(pid_, oep_addr, this->foreign_stack_, remote_memory_base + loaderSize);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    // Retrieve the handle
    SnapShotData<SnapShotCategory::Register> regs;
    err = SnapShot<SnapShotCategory::Register>(regs);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }
    injected_dl = regs.data.rax;
    if (injected_dl == 0)
    {
        return ErrorCode::INVALID_INTERNAL;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode ProcessHandler::start_thread(long fn_ptr) noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    if (this->injected_dl == 0)
    {
        return ErrorCode::INVALID_OPERATION;
    }

    auto clone_addr = target_libc_.getLibcBeginInMemory(get_maps()) +
                      target_libc_.getLibcFunctionOffset("clone");
    if (clone_addr == 0)
    {
        return ErrorCode::INVALID_INTERNAL;
    }

    this->SnapShotAll();
    defer([this]()
          { this->Restore(); });

    if (set_stack() != ErrorCode::SUCCESS)
    {
        return ErrorCode::INVALID_MEMORY;
    }

    // construct a clone remote call
    // remote_call
    long ret = 0;
    auto err = Ptrace::remote_call(pid_, clone_addr, ret, this->foreign_stack_, CLONE_VM | CLONE_THREAD, 0, 0, 0, fn_ptr, 0);
    if (err != ErrorCode::SUCCESS)
    {
        return err;
    }

    return ErrorCode::SUCCESS;
}

std::string ProcessHandler::get_target_exe(bool reload) noexcept
{
    if (reload || target_exe_.empty())
    {
        const auto target_exe = get_exe_path(pid_);
        target_exe_ = resolve_realpath(target_exe);
        target_exe_ = target_exe;
    }
    return target_exe_;
}

uint64_t ProcessHandler::get_inode_number(bool reload) noexcept
{
    if (reload || inode_ == 0)
    {
        inode_ = fetch_inode_number(get_exe_path(pid_));
    }
    return inode_;
}

uint64_t ProcessHandler::get_oep_address(bool reload) noexcept
{
    if (reload || oep_addr == 0)
    {
        oep_addr = fetch_oep_address(get_target_exe());
    }
    return oep_addr;
}

std::string ProcessHandler::get_maps() const noexcept
{
    const auto maps = std::string("/proc/") + std::to_string(pid_) + "/maps";
    std::ifstream maps_stream(maps);
    if (!maps_stream)
    {
        return "";
    }

    std::ostringstream buffer;
    buffer << maps_stream.rdbuf();
    return buffer.str();
}

std::string ProcessHandler::resolve_realpath(const std::string &path) const noexcept
{
    std::string result;
    constexpr auto PATH_MAX_ = 4096;
    result.resize(PATH_MAX_);

    ssize_t len = ::readlink(path.c_str(), result.data(), result.size());
    if (len == -1)
    {
        return "";
    }

    result.resize(len);
    return result;
}

uint64_t ProcessHandler::fetch_inode_number(const std::string &path) const noexcept
{
    struct stat st;
    if (stat(path.c_str(), &st) == -1)
    {
        return 0;
    }

    return st.st_ino;
}

uint64_t ProcessHandler::fetch_oep_address(const std::string &exe_path) const noexcept
{
    FileMapping fm(exe_path);
    if (!fm.isValid())
    {
        return 0;
    }

    const auto *base = fm.getBase();
    const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(base);
    return ehdr->e_entry;
}

uint64_t ProcessHandler::find_target_map_base(uint64_t inode_number) const noexcept
{
    const auto maps_content = get_maps();
    if (maps_content.empty())
    {
        return 0;
    }

    std::istringstream maps_stream(maps_content);
    std::string line;
    while (std::getline(maps_stream, line))
    {
        std::istringstream line_stream(line);
        std::string addr_range, perms, offset, dev, inode, pathname;
        line_stream >> addr_range >> perms >> offset >> dev >> inode;

        if (line_stream >> pathname)
        {
            if (std::stoull(inode) == inode_number && perms.find('x') != std::string::npos)
            {
                std::istringstream addr_stream(addr_range);
                std::string addr_start;
                std::getline(addr_stream, addr_start, '-');
                return std::stoull(addr_start, nullptr, 16);
            }
        }
    }
    return 0;
}

long ProcessHandler::alloc(uint32_t size, int PROT_, int flags) noexcept
{
#if defined(__x86_64__)
    constexpr int NR_mmap = 9;
#elif defined(__i386__)
    constexpr int NR_mmap = 192;
#else
    return 0;
#endif

    long ret = 0;
    auto err = Ptrace::remote_syscall(pid_, NR_mmap, ret, 0, size, PROT_, flags, -1, 0);
    if (err != ErrorCode::SUCCESS)
    {
        return 0;
    }

    return ret;
}

ErrorCode ProcessHandler::set_stack() noexcept
{
    if (!attached_)
    {
        return ErrorCode::INVALID_PROCESS;
    }

    if (this->foreign_stack_.base() == nullptr)
    {
        return Acquire(this->foreign_stack_, this->foreign_stack_.size());
    }
    return ErrorCode::SUCCESS;
}