#include <gtest/gtest.h>
#include <MyLibc.hpp>
#include <FileMapping.hpp>

#include <iostream>
#include <fstream>

#include <csignal>
#include <cstdio>
#include <execinfo.h>
#include <unistd.h>

void signal_handler(int signum)
{
    void *array[10];
    std::size_t size;

    // Get the array of pointers to the functions in the backtrace
    size = backtrace(array, 10);

    // Print the backtrace to stderr
    fprintf(stderr, "Error: signal %d:\n", signum);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

void setup_signal_handler()
{
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
}

class InvokeTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        setup_signal_handler();
    }
    MyLibc libc;
};

// test that I have the base of libc, and I have printf offset, i can get the address of printf
TEST_F(InvokeTest, GetLibcFunctionAddress)
{
    MyLibc libc;
    std::string libc_path = libc.getLibcPath();
    ASSERT_FALSE(libc_path.empty()) << "Libc path should not be empty.";

    bool result = libc.reloadLibcFunctions(libc_path);
    ASSERT_TRUE(result) << "Reloading libc functions should succeed.";

    FileMapping libc_mapping(libc_path, O_RDONLY | O_CLOEXEC);
    ASSERT_TRUE(libc_mapping.isValid()) << "Libc mapping should be valid.";

    auto *file_base = libc_mapping.getBase();
    ASSERT_NE(file_base, nullptr) << "Libc file base should not be nullptr.";

    std::string function_name = "printf";
    uint64_t offset = libc.getLibcFunctionOffset(function_name);
    ASSERT_NE(offset, 0) << "Offset for printf should not be zero.";

    uint8_t *printf_address = reinterpret_cast<uint8_t *>(file_base) + offset;
    ASSERT_NE(printf_address, nullptr) << "Address of printf should not be nullptr.";

    // print the file_base, printf address, and the offset
    std::cout << "file_base: " << file_base << std::endl;
    std::cout << "printf_address: " << (void *)printf_address << std::endl;
    std::cout << "offset: " << offset << std::endl;

    // print 40 bytes from the printf_address, 8 bytes per line
    for (int i = 0; i < 40; i += 8)
    {
        std::cout << std::hex << (int)printf_address[i] << " " << (int)printf_address[i + 1] << " " << (int)printf_address[i + 2] << " " << (int)printf_address[i + 3] << " " << (int)printf_address[i + 4] << " " << (int)printf_address[i + 5] << " " << (int)printf_address[i + 6] << " " << (int)printf_address[i + 7] << std::endl;
    }

    auto natural_printf = (void *)printf;
    std::cout << "natural printf: " << natural_printf << std::endl;

    auto *printf_ptr = reinterpret_cast<int (*)(const char *, ...)>(printf_address);
    ASSERT_NE(printf_ptr, nullptr) << "Pointer to printf should not be nullptr.";

    const char *message = "Hello, World!";
    getchar();
    testing::internal::CaptureStdout();
    // It SEGFAULT here, seems to be NX-bit or CET issue.
    printf_ptr("%s\n", message);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, std::string(message) + "\n") << "Output of printf should be correct.";
}