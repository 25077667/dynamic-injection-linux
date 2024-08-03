#ifndef __SCC_DLL_REMOTE_LOADER_HPP__
#define __SCC_DLL_REMOTE_LOADER_HPP__
#pragma once
#pragma GCC diagnostic ignored "-Wattributes"
#include <cstdint>
#include <cstring>
#include <dlfcn.h>

extern "C"
{
    struct RemoteLoaderArgs
    {
        void *handle;
        void *dlopenAddr;
        int dlFlags;
        char filePath[4]; // The file path of the shared library, C++ forbids flexible array members, 4 is dummy
    };

    __attribute__((section(".text"))) void RemoteLoader(RemoteLoaderArgs *args)
    {
        void *handle = nullptr;

        int dlFlags = args->dlFlags;
        const char *filePath = args->filePath;

        using DlopenFn = void *(*)(const char *, int);
        DlopenFn dlopen_fn = reinterpret_cast<DlopenFn>(args->dlopenAddr);
        handle = dlopen_fn(filePath, dlFlags);

        args->handle = handle;

        if (handle != nullptr)
            return;
    }

    extern "C" __attribute__((section(".text"))) void __loader_end() {}

    __attribute__((section(".text"), used, no_reorder)) extern "C" const uint32_t loaderSize = (uintptr_t)&__loader_end - (uintptr_t)&RemoteLoader;
}

#endif // __SCC_DLL_REMOTE_LOADER_HPP__