#include <DynamicLinkingLinux.hpp>
#include <ProcessHandler.hpp>
#include <SnapShotData.hpp>

#include <fstream>
#include <vector>

// Singleton instance retrieval
DynamicLinkingLinux &DynamicLinkingLinux::getInstance()
{
    static DynamicLinkingLinux instance;
    return instance;
}

ErrorCode DynamicLinkingLinux::inject_so(pid_t pid, const std::string &so_file_path)
{
    ProcessHandler processHandler(pid);

    // Attach to the process
    ErrorCode result = processHandler.attach();
    if (result != ErrorCode::SUCCESS)
    {
        return result;
    }

    // Take a snapshot of all data
    result = processHandler.SnapShotAll();
    if (result != ErrorCode::SUCCESS)
    {
        processHandler.detach();
        return result;
    }

    // Inject the shared object file
    result = processHandler.InjectCode(so_file_path);
    if (result != ErrorCode::SUCCESS)
    {
        processHandler.detach();
        return result;
    }

    // Restore the snapshot
    result = processHandler.Restore();
    if (result != ErrorCode::SUCCESS)
    {
        processHandler.detach();
        return result;
    }

    // Detach from the process
    return processHandler.detach();
}

ErrorCode DynamicLinkingLinux::find_function_address(pid_t pid, const std::string &function_signature, long &remote_addr)
{
    ProcessHandler processHandler(pid);

    // Attach to the process
    ErrorCode result = processHandler.attach();
    if (result != ErrorCode::SUCCESS)
    {
        return result;
    }

    // Ensure the shared object file has been injected
    // Assuming the ProcessHandler can check this (depends on internal implementation)
    if (processHandler.injected_dl == 0)
    {
        processHandler.detach();
        return ErrorCode::INVALID_OPERATION;
    }

    // Find the function entry point
    result = processHandler.FindEntry(function_signature, remote_addr);
    if (result != ErrorCode::SUCCESS)
    {
        processHandler.detach();
        return result;
    }

    // Detach from the process
    return processHandler.detach();
}

ErrorCode DynamicLinkingLinux::start_remote_thread(pid_t pid, long fn_ptr)
{
    ProcessHandler processHandler(pid);

    // Attach to the process
    ErrorCode result = processHandler.attach();
    if (result != ErrorCode::SUCCESS)
    {
        return result;
    }

    // Ensure the function address is valid
    if (fn_ptr == 0)
    {
        processHandler.detach();
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Start the thread
    result = processHandler.start_thread(fn_ptr);
    if (result != ErrorCode::SUCCESS)
    {
        processHandler.detach();
        return result;
    }

    // Detach from the process
    return processHandler.detach();
}

ErrorCode DynamicLinkingLinux::attach_to_process(pid_t pid)
{
    ProcessHandler processHandler(pid);
    return processHandler.attach();
}

ErrorCode DynamicLinkingLinux::detach_from_process(pid_t pid)
{
    ProcessHandler processHandler(pid);
    return processHandler.detach();
}
