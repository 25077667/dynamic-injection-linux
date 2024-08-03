#ifndef __SCC_DLL_THREAD_ATTR_HPP__
#define __SCC_DLL_THREAD_ATTR_HPP__
#pragma once

#include <stdexcept>
#include <cstddef>
#include <cstdint>

#include <pthread.h>
#include <sched.h>

struct ThreadAttr
{
    // Members to hold thread attributes
    int detachState = PTHREAD_CREATE_JOINABLE;
    std::size_t stackSize = 8192 * 1024; // default stack size is 8MB
    sched_param schedParam = {};
    int inheritSched = PTHREAD_INHERIT_SCHED;
    int schedPolicy = SCHED_OTHER;

    ThreadAttr() = default;
    ~ThreadAttr() = default;

    inline explicit ThreadAttr(const pthread_attr_t &attr)
    {
        if (pthread_attr_getdetachstate(&attr, &detachState) != 0 ||
            pthread_attr_getstacksize(&attr, &stackSize) != 0 ||
            pthread_attr_getschedparam(&attr, &schedParam) != 0 ||
            pthread_attr_getinheritsched(&attr, &inheritSched) != 0 ||
            pthread_attr_getschedpolicy(&attr, &schedPolicy) != 0)
        {
            throw std::runtime_error("Failed to initialize ThreadAttr from pthread_attr_t");
        }
    }

    // Conversion operator to pthread_attr_t
    inline operator pthread_attr_t() const
    {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, detachState);
        pthread_attr_setstacksize(&attr, stackSize);
        pthread_attr_setschedparam(&attr, &schedParam);
        pthread_attr_setinheritsched(&attr, inheritSched);
        pthread_attr_setschedpolicy(&attr, schedPolicy);
        return attr;
    }

    ThreadAttr(const ThreadAttr &) = delete;
    ThreadAttr &operator=(const ThreadAttr &) = delete;

    ThreadAttr(ThreadAttr &&) noexcept = default;
    ThreadAttr &operator=(ThreadAttr &&) noexcept = default;
};

#endif // __SCC_DLL_THREAD_ATTR_HPP__
