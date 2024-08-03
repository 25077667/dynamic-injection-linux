#ifndef __SCC_DLLL_SNAPSHOT_DATA_HPP__
#define __SCC_DLLL_SNAPSHOT_DATA_HPP__
#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <sys/user.h>

enum class SnapShotCategory
{
    Register,
    OEP,
};

template <SnapShotCategory>
struct SnapShotData
{
};

template <>
struct SnapShotData<SnapShotCategory::OEP>
{
    union
    {
        std::array<uint8_t, 64> data;
    };

    SnapShotData() : data{0} {}
    SnapShotData(const SnapShotData &) = default;
    SnapShotData(SnapShotData &&) noexcept = default;
    SnapShotData &operator=(const SnapShotData &) = default;
    SnapShotData &operator=(SnapShotData &&) noexcept = default;
    ~SnapShotData() = default;
};

template <>
struct SnapShotData<SnapShotCategory::Register>
{
    user_regs_struct data;

    SnapShotData() : data{} {}
    SnapShotData(const SnapShotData &) = default;
    SnapShotData(SnapShotData &&) noexcept = default;
    SnapShotData &operator=(const SnapShotData &) = default;
    SnapShotData &operator=(SnapShotData &&) noexcept = default;
    ~SnapShotData() = default;
};

#endif // __SCC_DLLL_SNAPSHOT_DATA_HPP__