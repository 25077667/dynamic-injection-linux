#include <gtest/gtest.h>
#include <MyLibc.hpp>

#include <fstream>

class MyLibcTest : public ::testing::Test
{
protected:
    MyLibc libc;
};

TEST_F(MyLibcTest, GetLibcPath)
{
    std::string libc_path = libc.getLibcPath();
    EXPECT_FALSE(libc_path.empty()) << "Libc path should not be empty.";
    std::ifstream file(libc_path);
    EXPECT_TRUE(file.is_open()) << "Libc path should point to an existing file.";
}

TEST_F(MyLibcTest, GetLibcFunctionOffset)
{
    std::string function_name = "printf";
    uint64_t offset = libc.getLibcFunctionOffset(function_name);
    EXPECT_NE(offset, 0) << "Offset for printf should not be zero.";
}

TEST_F(MyLibcTest, ReloadLibcFunctions)
{
    std::string libc_path = libc.getLibcPath();
    bool result = libc.reloadLibcFunctions(libc_path);
    EXPECT_TRUE(result) << "Reloading libc functions should succeed.";
}

TEST_F(MyLibcTest, GetLibcBaseOffset)
{
    std::string libc_path = libc.getLibcPath();
    uint64_t offset = libc.getLibcBaseOffset(libc_path);
    EXPECT_NE(offset, 0) << "Base offset for libc should not be zero.";
}

// print the libc_functions_
// TEST_F(MyLibcTest, PrintLibcFunctions)
// {
//     struct Tmp : public MyLibc
//     {
//         void printLibcFunctions()
//         {
//             for (const auto &entry : libc_functions_)
//             {
//                 std::cout << entry.first << " : " << std::hex << entry.second << std::endl;
//             }
//         }
//     };

//     Tmp tmp;
//     tmp.reloadLibcFunctions(tmp.getLibcPath());
//     tmp.printLibcFunctions();
// }
