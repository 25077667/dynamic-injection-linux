#include <DynamicLinkingLinux.hpp>
#include <fstream>
#include <iostream>

static void others();

extern "C"
{
    SCC_ENTRY_FUNCTION(helloworld);
}

void helloworld()
{
    std::ofstream outFile("/tmp/helloworld_log.txt");
    if (outFile.is_open())
        outFile << "Hello, World!\n";

    others();
}

void others()
{
    std::cout << __PRETTY_FUNCTION__ << std::endl;
}