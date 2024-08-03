HANDLE __stdcall CreateRemoteThread(HANDLE hProcess,
                                    LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                    SIZE_T dwStackSize,
                                    LPTHREAD_START_ROUTINE lpStartAddress,
                                    LPVOID lpParameter,
                                    DWORD dwCreationFlags,
                                    LPDWORD lpThreadId)
{
    HANDLE pvVar1;
    /* 0x39b90  234  CreateRemoteThread */
    pvVar1 = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                  dwCreationFlags & 0x10004, (LPPROC_THREAD_ATTRIBUTE_LIST)0x0, lpThreadId);
    return pvVar1;
}
