#ifndef __SCC_DYNAMIC_LINKING_LINUX_HPP__
#define __SCC_DYNAMIC_LINKING_LINUX_HPP__

#pragma once

#include <cstddef>
#include <string>
#include <vector>

/**
 * @enum ErrorCode
 * @brief Enumeration representing various error codes that can be returned by the functions.
 */
enum class ErrorCode
{
    SUCCESS = 0,
    INVALID_CODE,
    INVALID_CODE_SIZE,
    INVALID_INJECTION_SIZE,
    INVALID_INJECTION_ADDRESS,
    INVALID_INJECTION,
    INVALID_ENTRY_FUNCTION,
    INVALID_PROCESS,
    INVALID_THREAD,
    INVALID_IO,
    INVALID_OPERATION,
    INVALID_PERMISSION,
    INVALID_MEMORY,
    INVALID_REGISTER,
    INVALID_SYSTEM,
    INVALID_INTERNAL,
    INVALID_ARGUMENT,
    PROCESS_EXITED,
    INVALID_UNKNOWN,
};

/**
 * @brief Macro to define the entry function for the injected code.
 * @param entry_func The entry function to be marked as the entry point.
 */
#define SCC_ENTRY_FUNCTION(entry_func) \
    __attribute__((section(".scc_entry"))) void entry_func()

/**
 * @class DynamicLinkingLinux
 * @brief Singleton class providing functionality for dynamic linking and DLL injection in Linux.
 */
class DynamicLinkingLinux
{
public:
    /**
     * @brief Retrieves the singleton instance of the DynamicLinkingLinux class.
     * @return Reference to the singleton instance.
     */
    static DynamicLinkingLinux &getInstance();

    /**
     * @brief Injects a shared object (SO) file into a target process.
     * @param pid The process identifier of the target process.
     * @param so_file_path The path to the shared object file to be injected.
     * @return ErrorCode indicating the result of the injection operation.
     */
    ErrorCode inject_so(pid_t pid, const std::string &so_file_path);

    /**
     * @brief Finds the address of a function in the injected shared object file within the target process.
     * This function depends on the successful injection of the shared object file using inject_so.
     * @param pid The process identifier of the target process.
     * @param function_signature The signature of the function to be found.
     * @param remote_addr Reference to a variable where the address of the function entry point will be stored.
     * @return ErrorCode indicating the result of the search operation.
     */
    ErrorCode find_function_address(pid_t pid, const std::string &function_signature, long &remote_addr);

    /**
     * @brief Starts a new thread in the target process to execute the specified function.
     * This function depends on the successful injection of the shared object file using inject_so
     * and finding the function address using find_function_address.
     * @param pid The process identifier of the target process.
     * @param fn_ptr The address of the function to be executed in the new thread.
     * @return ErrorCode indicating the result of the thread start operation.
     */
    ErrorCode start_remote_thread(pid_t pid, long fn_ptr);

    // Delete copy constructor and assignment operator to enforce singleton pattern
    DynamicLinkingLinux(const DynamicLinkingLinux &) = delete;
    DynamicLinkingLinux &operator=(const DynamicLinkingLinux &) = delete;

private:
    /**
     * @brief Private constructor to enforce the singleton pattern.
     */
    DynamicLinkingLinux() = default;

    /**
     * @brief Attaches to the target process.
     * @param pid The process identifier of the target process.
     * @return ErrorCode indicating the result of the attach operation.
     */
    ErrorCode attach_to_process(pid_t pid);

    /**
     * @brief Detaches from the target process.
     * @param pid The process identifier of the target process.
     * @return ErrorCode indicating the result of the detach operation.
     */
    ErrorCode detach_from_process(pid_t pid);
};

#endif // __SCC_DYNAMIC_LINKING_LINUX_HPP__
