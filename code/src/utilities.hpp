#ifndef __SCC_DLL_UTILITIES_HPP__
#define __SCC_DLL_UTILITIES_HPP__
#pragma once

template <typename F>
struct defer
{
    F f;
    defer(F f) : f(f) {}
    ~defer() { f(); }
};

#endif // __SCC_DLL_UTILITIES_HPP__