#include <ProcessHandler.hpp>
#include <MyLibc.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <iostream>

#include <signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <execinfo.h>

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

class MockMyLibc : public MyLibcBase
{
public:
    MOCK_METHOD(std::string, getLibcPath, (const std::string &target_process_maps), (const, noexcept, override));
    MOCK_METHOD(uint64_t, getLibcFunctionOffset, (const std::string &function_name), (const, noexcept, override));
    MOCK_METHOD(bool, reloadLibcFunctions, (const std::string &libc_path), (noexcept, override));
    MOCK_METHOD(uint64_t, getLibcBaseOffset, (const std::string &libc_path), (noexcept, override));
};

class ProcessHandlerTestable : public ProcessHandler
{
public:
    using ProcessHandler::attached_;
    using ProcessHandler::get_inode_number;
    using ProcessHandler::get_oep_address;
    using ProcessHandler::get_target_exe;
    using ProcessHandler::ProcessHandler;

    ProcessHandlerTestable(pid_t pid, MyLibc target_libc) : ProcessHandler(pid, target_libc) {}

    template <SnapShotCategory category>
    ErrorCode SnapShot(SnapShotData<category> &data)
    {
        return ProcessHandler::SnapShot<category>(data);
    }

    template <SnapShotCategory category>
    ErrorCode Restore(const SnapShotData<category> &data)
    {
        return ProcessHandler::Restore<category>(data);
    }

    using ProcessHandler::SnapShotAll;
};

class ProcessHandlerTest : public ::testing::Test
{
protected:
    pid_t child_pid;
    ProcessHandlerTestable *handler_ = nullptr;
    MyLibc mock_libc_;

    void SetUp() override
    {
        setup_signal_handler();

        child_pid = fork();
        if (child_pid == 0)
        {
            // Child process: sleep to keep it running
            while (true)
            {
                sleep(1);
            }
        }
        else
        {
            handler_ = new ProcessHandlerTestable(child_pid, mock_libc_);
        }
    }

    void TearDown() override
    {
        if (child_pid > 0)
        {
            handler_->detach();

            // Parent process: kill the child process
            kill(child_pid, SIGKILL);
            waitpid(child_pid, nullptr, 0);

            delete handler_;
        }
    }
};
// Test attach method success
TEST_F(ProcessHandlerTest, AttachSucceeds)
{
    EXPECT_EQ(handler_->attach(), ErrorCode::SUCCESS);
    EXPECT_TRUE(handler_->attached_);
}

// Test detach method success
TEST_F(ProcessHandlerTest, DetachSucceeds)
{
    handler_->attach(); // First attach to ensure it can detach

    EXPECT_EQ(handler_->detach(), ErrorCode::SUCCESS);
    EXPECT_FALSE(handler_->attached_);
}

// Test SnapShot method for OEP
TEST_F(ProcessHandlerTest, SnapShotOEPSucceeds)
{
    handler_->attach();
    SnapShotData<SnapShotCategory::OEP> oep_data;
    EXPECT_EQ(handler_->SnapShot<SnapShotCategory::OEP>(oep_data), ErrorCode::SUCCESS);
    // std::cerr << "OEP: " << (int)oep_data.data[0] << std::endl;
}

// Test SnapShot method for Register
TEST_F(ProcessHandlerTest, SnapShotRegisterSucceeds)
{
    handler_->attach();
    SnapShotData<SnapShotCategory::Register> register_data;
    EXPECT_EQ(handler_->SnapShot<SnapShotCategory::Register>(register_data), ErrorCode::SUCCESS);
}

// Test Restore method for OEP
TEST_F(ProcessHandlerTest, RestoreOEPSucceeds)
{
    handler_->attach();
    SnapShotData<SnapShotCategory::OEP> orig_oep_data;
    handler_->SnapShot<SnapShotCategory::OEP>(orig_oep_data);

    // overwrite the original OEP data, with all elements set to 0
    SnapShotData<SnapShotCategory::OEP> oep_data;
    std::fill(oep_data.data.begin(), oep_data.data.end(), 0);
    EXPECT_EQ(handler_->Restore<SnapShotCategory::OEP>(oep_data), ErrorCode::SUCCESS);

    // check if the OEP data has been overwritten
    SnapShotData<SnapShotCategory::OEP> restored_oep_data;
    handler_->SnapShot<SnapShotCategory::OEP>(restored_oep_data);

    // use for loop to compare each element
    for (std::size_t i = 0; i < orig_oep_data.data.size(); ++i)
    {
        EXPECT_EQ(restored_oep_data.data[i], oep_data.data[i]);
    }
}

// Test Restore method for Register
TEST_F(ProcessHandlerTest, RestoreRegisterSucceeds)
{
    handler_->attach();
    SnapShotData<SnapShotCategory::Register> register_data;
    handler_->SnapShot<SnapShotCategory::Register>(register_data);
    EXPECT_EQ(handler_->Restore<SnapShotCategory::Register>(register_data), ErrorCode::SUCCESS);
}

// Test SnapShotAll method
TEST_F(ProcessHandlerTest, SnapShotAllSucceeds)
{
    handler_->attach();
    EXPECT_EQ(handler_->SnapShotAll(), ErrorCode::SUCCESS);
}

// Test protected methods
TEST_F(ProcessHandlerTest, GetTargetExeReturnsCorrectPath)
{
    EXPECT_EQ(handler_->get_target_exe(), "/proc/" + std::to_string(child_pid) + "/exe");
}

TEST_F(ProcessHandlerTest, GetInodeNumberWorksCorrectly)
{
    EXPECT_GT(handler_->get_inode_number(), 0); // Inode number should be greater than 0
}
