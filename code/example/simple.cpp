#include <DynamicLinkingLinux.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cerr << "Usage: sudo " << argv[0] << " <pid> <so_file>\n";
        std::cerr << "Don't forget to turn off ptrace_scope:\n";
        std::cerr << "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n";
        return 1;
    }

    long target_pid = std::stol(argv[1]);
    std::string so_file_path = argv[2];

    DynamicLinkingLinux &dll = DynamicLinkingLinux::getInstance();

    // Inject the shared object file into the target process
    ErrorCode error = dll.inject_so(target_pid, so_file_path);
    if (error != ErrorCode::SUCCESS)
    {
        std::cerr << "Injection failed with error code: " << static_cast<int>(error) << "\n";
        return 1;
    }

    long function_address = 0;
    std::string function_signature = "your_function_signature"; // Replace with your actual function signature

    // Find the function address in the injected SO file
    error = dll.find_function_address(target_pid, function_signature, function_address);
    if (error != ErrorCode::SUCCESS)
    {
        std::cerr << "Failed to find function address with error code: " << static_cast<int>(error) << "\n";
        return 1;
    }

    // Start a new thread in the target process to execute the function
    error = dll.start_remote_thread(target_pid, function_address);
    if (error != ErrorCode::SUCCESS)
    {
        std::cerr << "Failed to start remote thread with error code: " << static_cast<int>(error) << "\n";
        return 1;
    }

    std::cout << "Injection and thread start successful\n";
    return 0;
}
