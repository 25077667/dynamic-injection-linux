#ifndef __SCC_DLL_MY_LIBC_HPP__
#define __SCC_DLL_MY_LIBC_HPP__
#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>

/**
 * @brief Represents an interface for the system libc wrapper.
 *
 * This interface provides functionality to retrieve the system libc file path,
 * maintain a table of libc function offsets, and retrieve the offset of a specific libc function.
 */
struct MyLibcBase
{
public:
    virtual ~MyLibcBase() = default;

    virtual std::string getLibcPath(const std::string &target_process_maps = "/proc/self/maps") const noexcept = 0;
    virtual uint64_t getLibcFunctionOffset(const std::string &function_name) const noexcept = 0;
    virtual bool reloadLibcFunctions(const std::string &libc_path) noexcept = 0;
    virtual uint64_t getLibcBaseOffset(const std::string &libc_path) noexcept = 0;
};

/**
 * @brief Represents a wrapper class for the system libc.
 *
 * This class provides functionality to retrieve the system libc file path,
 * maintain a table of libc function offsets, and retrieve the offset of a specific libc function.
 */
struct MyLibc : public MyLibcBase
{
    MyLibc(const std::string &target_process_maps = "/proc/self/maps");
    ~MyLibc() = default;

    /**
     * @brief Retrieves the file path of the system libc.
     *
     * @return The file path of the system libc, return empty string if failed.
     */
    std::string getLibcPath(const std::string &target_process_maps) const noexcept override;

    inline std::string getLibcPath() const noexcept
    {
        return getLibcPath("/proc/self/maps");
    }

    /**
     * @brief Retrieves the offset of a specific libc function.
     *
     * @param function_name The name of the libc function.
     * @return The offset of the specified libc function, null if the function is not found.
     */
    uint64_t getLibcFunctionOffset(const std::string &function_name) const noexcept override;

    /**
     * @brief Reloads the libc functions and their offsets.
     *
     * This function reloads the libc functions and their offsets from the system libc file.
     * @param libc_path The file path of the system libc.
     * @return True if the libc functions were successfully reloaded, false otherwise.
     */
    bool reloadLibcFunctions(const std::string &libc_path) noexcept override;

    /**
     * @brief Retrieves the .text section offset of the system libc.
     *
     * @param libc_path The file path of the system libc.
     * @return The .text section offset of the system libc, null if the libc file is not found.
     */
    uint64_t getLibcBaseOffset(const std::string &libc_path) noexcept override;

    /**
     * @brief Retrieves the base address of the system libc in memory.
     * @param target_process_maps The maps' content of the target process.
     * @return The base address of the system libc in memory.
     */
    uint64_t getLibcBeginInMemory(const std::string &target_process_maps) noexcept;

protected:
    /**
     * @brief Builds the table of libc functions and their offsets.
     *
     * This function builds the table of libc functions and their offsets from the system libc file.
     * @param libc_path The file path of the system libc.
     * @return True if the libc functions table was successfully built, false otherwise.
     */
    bool buildLibcFunctionsTable(const std::string &libc_path) noexcept;

    uint64_t maps_begin_ = 0;                                  // The beginning address for /proc/pid/maps for libc.
    std::string libc_path_;                                    // The file path of the system libc.
    uint64_t libc_base_offset_ = 0;                            // The base address offset since the file beginning.
    std::unordered_map<std::string, uint64_t> libc_functions_; // Table of libc function offsets.
};

#endif // __SCC_DLL_MY_LIBC_HPP__