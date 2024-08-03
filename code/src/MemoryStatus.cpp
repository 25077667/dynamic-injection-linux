#include <MemoryStatus.hpp>

#include <unordered_map>
#include <sstream>
#include <string_view>
#include <sstream>

const static inline std::unordered_map<MemoryStatus::VmFlags, std::string_view> VmFlagToString = {
    {MemoryStatus::VmFlags::RD, "rd"},
    {MemoryStatus::VmFlags::WR, "wr"},
    {MemoryStatus::VmFlags::EX, "ex"},
    {MemoryStatus::VmFlags::SH, "sh"},
    {MemoryStatus::VmFlags::MR, "mr"},
    {MemoryStatus::VmFlags::MW, "mw"},
    {MemoryStatus::VmFlags::ME, "me"},
    {MemoryStatus::VmFlags::MS, "ms"},
    {MemoryStatus::VmFlags::GD, "gd"},
    {MemoryStatus::VmFlags::PF, "pf"},
    {MemoryStatus::VmFlags::DW, "dw"},
    {MemoryStatus::VmFlags::LO, "lo"},
    {MemoryStatus::VmFlags::IO, "io"},
    {MemoryStatus::VmFlags::SR, "sr"},
    {MemoryStatus::VmFlags::RR, "rr"},
    {MemoryStatus::VmFlags::DC, "dc"},
    {MemoryStatus::VmFlags::DE, "de"},
    {MemoryStatus::VmFlags::AC, "ac"},
    {MemoryStatus::VmFlags::NR, "nr"},
    {MemoryStatus::VmFlags::HT, "ht"},
    {MemoryStatus::VmFlags::AR, "ar"},
    {MemoryStatus::VmFlags::DD, "dd"},
    {MemoryStatus::VmFlags::SD, "sd"},
    {MemoryStatus::VmFlags::MM, "mm"},
    {MemoryStatus::VmFlags::HG, "hg"},
    {MemoryStatus::VmFlags::NH, "nh"},
    {MemoryStatus::VmFlags::MG, "mg"},
};

const static inline std::unordered_map<std::string_view, MemoryStatus::VmFlags> StringToVmFlag = {
    {"rd", MemoryStatus::VmFlags::RD},
    {"wr", MemoryStatus::VmFlags::WR},
    {"ex", MemoryStatus::VmFlags::EX},
    {"sh", MemoryStatus::VmFlags::SH},
    {"mr", MemoryStatus::VmFlags::MR},
    {"mw", MemoryStatus::VmFlags::MW},
    {"me", MemoryStatus::VmFlags::ME},
    {"ms", MemoryStatus::VmFlags::MS},
    {"gd", MemoryStatus::VmFlags::GD},
    {"pf", MemoryStatus::VmFlags::PF},
    {"dw", MemoryStatus::VmFlags::DW},
    {"lo", MemoryStatus::VmFlags::LO},
    {"io", MemoryStatus::VmFlags::IO},
    {"sr", MemoryStatus::VmFlags::SR},
    {"rr", MemoryStatus::VmFlags::RR},
    {"dc", MemoryStatus::VmFlags::DC},
    {"de", MemoryStatus::VmFlags::DE},
    {"ac", MemoryStatus::VmFlags::AC},
    {"nr", MemoryStatus::VmFlags::NR},
    {"ht", MemoryStatus::VmFlags::HT},
    {"ar", MemoryStatus::VmFlags::AR},
    {"dd", MemoryStatus::VmFlags::DD},
    {"sd", MemoryStatus::VmFlags::SD},
    {"mm", MemoryStatus::VmFlags::MM},
    {"hg", MemoryStatus::VmFlags::HG},
    {"nh", MemoryStatus::VmFlags::NH},
    {"mg", MemoryStatus::VmFlags::MG},
};

std::string MemoryStatus::vmFlagsToString(const std::vector<MemoryStatus::VmFlags> &flags) noexcept
{
    if (flags.empty())
    {
        return "";
    }

    std::ostringstream result;
    auto it = flags.begin();
    result << VmFlagToString.at(*it); // Safely access the first element
    ++it;

    for (; it != flags.end(); ++it)
    {
        result << ' ' << VmFlagToString.at(*it); // Append remaining elements with a space
    }
    return result.str();
}

std::vector<MemoryStatus::VmFlags> MemoryStatus::stringToVmFlags(const std::string &vmFlagsStr) noexcept
{
    std::vector<MemoryStatus::VmFlags> flags;
    std::size_t start = 0, end = 0;
    std::string_view vmFlagsView = vmFlagsStr; // Create a string_view over the entire string

    while ((end = vmFlagsView.find(' ', start)) != std::string::npos)
    {
        std::string_view flagStr = vmFlagsView.substr(start, end - start);
        auto it = StringToVmFlag.find(flagStr);
        if (it != StringToVmFlag.end())
        {
            flags.push_back(it->second);
        }
        start = end + 1;
    }

    std::string_view lastFlag = vmFlagsView.substr(start);
    if (!lastFlag.empty())
    {
        auto it = StringToVmFlag.find(lastFlag);
        if (it != StringToVmFlag.end())
        {
            flags.push_back(it->second);
        }
    }

    return flags;
}