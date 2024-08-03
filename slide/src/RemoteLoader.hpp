extern "C" {
    struct RemoteLoaderArgs {
        void *handle;
        void *dlopenAddr;
        int dlFlags;
        char filePath[256];
    };

    __attribute__((section(".text"))) void RemoteLoader(RemoteLoaderArgs *args) {
        void *handle = nullptr;
        int dlFlags = args->dlFlags;
        const char *filePath = args->filePath;

        using DlopenFn = void *(*)(const char *, int);
        DlopenFn dlopen_fn = reinterpret_cast<DlopenFn>(args->dlopenAddr);
        handle = dlopen_fn(filePath, dlFlags);

        args->handle = handle;
        args->filePath[0] = '\0';

        if (handle != nullptr)
            return;
    }
    extern "C" __attribute__((section(".text"))) void __loader_end() {}
    __attribute__((section(".text"), used, no_reorder)) extern "C" const uint32_t loaderSize = (uintptr_t)&__loader_end - (uintptr_t)&RemoteLoader;
}