# Dynamic Linking in Linux (DLL) Injection Project

## Introduction 🚀

Welcome to the Dynamic Linking in Linux (DLL) Injection Project! Inspired by the widely recognized "DLL Injection" technique from Windows, this project brings the power and flexibility of dynamic code injection to Linux environments. The essence of DLL injection involves inserting code into the address space of another process, enabling the execution of custom code within the context of another running program. This project aims to provide tools and methods for performing such injections in a Linux setting, focusing on ethical usage such as debugging, performance monitoring, reverse engineering, and enhancing application functionalities without altering their source code.

## Usage Example 🚀

This section demonstrates how to use the DLL Injection Project to inject custom code into a Linux process. The example consists of two parts: `example.cpp`, the injector program, and `to_be_injected.cpp`, the code to be injected.

### Preparing the Injectable Code

First, let's prepare the code that we want to inject. This example injects a simple "Hello, World!" message into a file from the target process. The code for this is in `to_be_injected.cpp`.

```cpp
// to_be_injected.cpp
#include <DynamicLinkingLinux.hpp>
#include <fstream>

extern "C" {
    SCC_ENTRY_FUNCTION(helloworld);
}

void helloworld() {
    std::ofstream outFile("/tmp/helloworld_log.txt");
    if (outFile.is_open())
        outFile << "Hello, World!\n";
}
```

Compile this code into a shared object (`hello_world.so`) using the following command:

```sh
g++ -std=c++11 -fPIC -shared to_be_injected.cpp -o hello_world.so
```

### Creating the Injector

Next, we have the injector program in `example.cpp`. This program injects the shared object file into the target process, finds a function within the injected code, and starts a new thread in the target process to execute the function.

```cpp
// example.cpp
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
    std::string function_signature = "helloworld"; // Replace with your actual function signature

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
```

### Compiling and Running the Injector

Compile `example.cpp` with:

```sh
g++ -std=c++11 example.cpp -o injector -ldl
```

Run the injector (you might need appropriate permissions or use sudo):

```sh
sudo ./injector <pid> hello_world.so
```

### Expected Outcome

After running the injector, check `/tmp/helloworld_log.txt` on your system. If the injection was successful, you'll find a "Hello, World!" message written by the injected code.

## License 📜

This project is licensed under the GPLv3 License. This ensures that the software remains free and open-source, and it encourages contributions and modifications under the same license. For more details, see the LICENSE file in the project repository.

## Project Highlights ✨

- **Ethical Focus**: Aimed at promoting ethical applications of dynamic code injection, this project can be a valuable tool for software developers, security researchers, and system administrators.
- **Migrating-Platform Compatibility**: Though inspired by a technique commonly used in Windows, this project is specifically tailored for Linux, filling a gap in the Linux software ecosystem.
- **Community-Driven**: Licensed under GPLv3, we welcome contributions, improvements, and innovations from the community.

## Building the Project 🛠️

This project uses CMake and Ninja as its build system, making it straightforward to compile and run across different Linux distributions. Here's how you can build the project:

### Prerequisites

Ensure you have `cmake` and `ninja` installed on your system. You can install these tools using your distribution's package manager. For example, on Ubuntu, you can install them using:

```bash
sudo apt-get update
sudo apt-get install cmake ninja-build
```

### Compiling the Project

1. **Clone the Repository**: First, clone the project repository to your local machine.

```bash
git clone https://github.com/25077667/dynamic-injection-linux.git
cd dynamic-injection-linux
```

2. **Prepare the Build System**: Use CMake to generate the Ninja build files.

```bash
cmake -S . -B build -G Ninja
```

3. **Build the Project**: Now, compile the project with Ninja.

```bash
ninja -C build
```

### Running Examples

To see the dynamic linking in action, you can run the provided examples located under the `example/` directory.

```bash
cd build/example
./example
```

## Contributing 🤝

We encourage contributions from the community, whether it's adding new features, fixing bugs, or improving documentation. Please adhere to our ethical usage guidelines and ensure all contributions are compliant with the GPLv3 License.

Enjoy exploring and contributing to the Dynamic Linking in Linux Injection Project! 🎉
