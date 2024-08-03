HANDLE __stdcall CreateRemoteThreadEx(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
{
    bool threadCreationSuccess;
    int status;
    HMODULE moduleHandle;
    FARPROC csrCreateRemoteThread;
    HANDLE threadHandle;
    char *debugMessage;
    PVOID returnAddress;
    uint64_t securityCookie;
    PVOID localPointer;
    uint64_t localStackSize;
    uint64_t localCreationFlags;
    uint64_t localParameter;
    int64_t *localPointerToStack;
    uint64_t localThreadStart;
    uint64_t localThreadParameter;
    uint64_t localThreadAttributes;
    uint64_t localThreadFlags;
    uint64_t localThreadSecurity;
    uint64_t localThreadHandle;
    int64_t *localStackPointer;
    uint *localAttributes;
    uint64_t localThreadId;
    uint64_t localThreadAddress;
    uint64_t localContext;
    uint64_t localContextStack;
    uint64_t localContextAttributes;
    uint64_t localAttributesSize;
    uint64_t localAttributesPointer;
    uint64_t localThreadStack;
    uint64_t localThreadSecurityCookie;
    uint64_t localContextInfo;
    uint64_t localContextParameters;
    int64_t *localContextStackPointer;
    uint localAttributeFlags;
    uint localThreadCreationFlags;
    int localThreadStatus;
    int64_t localThreadHandlePointer;
    uint localThreadInformation[2];
    HANDLE localProcessHandle;
    PVOID localObjectAttributes;
    int64_t localContextStackHandle;
    uint localContextAttributesFlags[2];
    int64_t localContextInfoPointer;
    PVOID localContextStackPointerData;
    SIZE_T localStackSizePointer;
    PVOID localParameterPointer;
    LPTHREAD_START_ROUTINE localStartAddress;
    uint64_t localThreadContext;
    uint localThreadContextFlags[4];
    PVOID localStackAttributes[4];
    PVOID localObjectAttributesPointer[8];
    PVOID localThreadStackAttributes[8];
    PVOID localThreadStackAttributesPointer[8];
    PVOID localThreadObjectAttributesPointer[8];
    int localObjectAttributesStatus;
    uint localObjectAttributesInformation[12];
    int64_t localObjectAttributesStackPointer;
    uint64_t localObjectAttributesFlags;
    uint64_t localContextFlags;
    int64_t *localContextStackPointerDataPointer;
    uint64_t localContextFlagsPointer;
    uint64_t localContextAttributesFlagsPointer;
    uint64_t localContextParametersPointer;
    uint64_t localContextInfoPointerData;
    uint localContextParametersFlags;
    PVOID localContextAttributesFlagsPointerData[16];
    PVOID localContextFlagsPointerData[32];
    PVOID localContextParametersFlagsPointerData[8];
    PVOID localObjectAttributesFlagsPointerData[16];
    PVOID localObjectAttributesFlagsPointer[32];
    int localContextAttributesPointerStatus;
    PVOID localObjectAttributesStackPointerData[48];
    int64_t localContextInfoPointerDataPointer;
    uint64_t localContextFlagsPointerDataPointer;
    uint64_t localObjectAttributesFlagsPointerDataPointer;
    PVOID localObjectAttributesStackPointerDataPointer[16];
    uint64_t localContextFlagsPointerDataPointerData;
    int64_t *localContextStackPointerDataPointerPointer;
    uint64_t localContextParametersFlagsPointerDataPointer;
    uint64_t securityCookieCheck;

    // Initialize security cookie
    securityCookieCheck = DAT_18028be70 ^ (uint64_t)securityCookie;

    // Initialize local variables
    localParameterPointer = (PVOID)lpParameter;
    localThreadCreationFlags = 0;
    localObjectAttributesFlagsPointerDataPointer = 0;
    localContextStackHandle = 0;
    localThreadContextFlags[0] = 0;
    localThreadStatus = 0;
    localThreadHandlePointer = 0;
    localStackSizePointer = dwStackSize;
    localStartAddress = lpStartAddress;

    if ((dwCreationFlags & 0xfffefffb) == 0)
    {
        localThreadStatus = BaseFormatObjectAttributes(localObjectAttributesPointer, 0, 0);
        status = localThreadStatus;
        if (status >= 0)
        {
            // Initialize thread attributes
            localThreadFlags = 0x10003;
            localThreadAttributes = 0x10;
            localThreadParameter = 0;
            localThreadContext = (uint64_t)localThreadContextFlags;
            localThreadHandle = 0x10004;
            localContextStack = 8;
            localContext = 0;
            localContextStackPointer = &localContextInfoPointer;
            localThreadInformation[0] = 2;

            // If lpAttributeList is not null, set up attributes
            if (lpAttributeList != NULL)
            {
                localAttributeFlags = 0x1c;
                localAttributes = localThreadInformation;
                localStackPointer = &localContextInfoPointerDataPointer;
                localThreadSecurity = 0;
                localContextAttributes = 0;
                localThreadAttributesPointer = 0;
                localObjectAttributesPointer = 0;
                localObjectAttributesStatus = 0;
                localContextAttributesPointerStatus = 0;
                localContextStackPointerDataPointerPointer = 0;
                localContextFlags = 0;
                localContextParameters = 0;
                localContextParametersPointer = 0;
                localContextFlagsPointer = 0;
                localContextFlagsPointerDataPointer = 0;
                localContextParametersFlagsPointer = 0;
                localThreadId = 0;
                localThreadAddress = 0;
                localContextAttributesPointer = (PVOID)0;
                localContextAttributesFlags = 0;
                localContextParametersFlags = 0;
                localContextInfo = 0;
                localContextStackPointerData = (PVOID)0;
                localContextStackPointerDataPointerData = 0;
                localContextStackPointerDataPointer = 0;
                localThreadStatus = InitializeProcThreadAttributeList(lpAttributeList, 1, localContextAttributesFlags);
                status = localThreadStatus;
                if (localThreadStatus < 0)
                    goto cleanup;
            }

            localContextStackPointerDataPointerPointer = (int64_t *)((uint64_t)localThreadInformation[0] * 0x20 + 8);
            localProcessHandle = NULL;
            threadCreationSuccess = true;

            if (hProcess != (HANDLE)-1)
            {
                localContextParametersFlagsPointerDataPointer = localContextParametersFlagsPointerDataPointer & 0xffffffff00000000;
                localContextAttributesPointer = (PVOID)((uint64_t)localContextAttributesPointer & 0xffffffff00000000);
                localThreadStack = CONCAT44(localThreadStack._4_4_, 0x402);
                status = NtDuplicateObject((HANDLE)-1, hProcess, (HANDLE)-1, &localProcessHandle);
                if (status >= 0)
                {
                    hProcess = localProcessHandle;
                }
                localThreadStack = 0;
                localThreadStatus = NtQueryInformationProcess(hProcess, 0, localThreadObjectAttributesPointer);
                if ((localThreadStatus >= 0) && (localObjectAttributesPointer != ClientId.UniqueProcess))
                {
                    threadCreationSuccess = false;
                    localThreadStack = 0;
                    localThreadStatus = NtQueryInformationProcess(hProcess, 0x25, localObjectAttributesFlagsPointer);
                    if ((localThreadStatus >= 0) && (localObjectAttributesStatus - 2U > 1))
                    {
                        localThreadStatus = -0x3fffffff;
                    }
                }
                status = localThreadStatus;
                if (localThreadStatus < 0)
                {
                    if (localProcessHandle != NULL)
                    {
                        NtClose();
                    }
                    goto cleanup;
                }
            }

            if (threadCreationSuccess)
            {
                localContextParametersFlagsPointer = 0;
                localContextAttributesPointer = (PVOID)0x10;
                localThreadStack = (PVOID)localObjectAttributesFlagsPointerData;
                status = RtlQueryInformationActivationContext(1, 0, 0);
                localThreadStatus = status;
                if (status >= 0)
                {
                    if (((DAT_18028cc84 != '\0') || (SubProcessTag != NULL)) ||
                        ((localObjectAttributesFlagsPointerData._0_8_ != 0 && ((localObjectAttributesFlagsPointerData & (PVOID)0x1) == (PVOID)0x0))))
                    {
                        localThreadCreationFlags = 1;
                        goto thread_create;
                    }
                    localThreadCreationFlags = 0;
                    goto resume_thread;
                }
                DbgPrint("SXS: %s - Failing thread create because RtlQueryInformationActivationContext() failed with status %08lx\n", "CreateRemoteThreadEx", status);
            }
            else
            {
            thread_create:
                if (localThreadCreationFlags == 0)
                {
                resume_thread:
                    localContextAttributesFlags[0] = 0;
                    if ((dwCreationFlags & 4) != 0)
                        goto creation_flags;
                }
                else
                {
                creation_flags:
                    localContextAttributesFlags[0] = 1;
                }

                localContextFlagsPointer = -(uint64_t)((dwCreationFlags & 0x10000) != 0) & localStackSizePointer;
                localContextFlagsPointerData = localStackSizePointer;
                if ((dwCreationFlags & 0x10000) != 0)
                {
                    localContextFlagsPointerData = 0;
                }
                localContextStackPointerDataPointer = &localContextInfoPointerDataPointer;
                localContextAttributesPointerStatus = 0;
                localContextParametersFlagsPointerDataPointer = CONCAT44(localContextParametersFlagsPointerDataPointer._4_4_, localContextAttributesFlags[0]);
                localContextAttributesPointer = localParameterPointer;
                localThreadStack = localStartAddress;
                status = NtCreateThreadEx(&localThreadHandlePointer, 0x1fffff, localContextParametersPointer, hProcess);
                localThreadStatus = status;
                if (status >= 0)
                {
                    if (localThreadCreationFlags != 0)
                    {
                        if (SubProcessTag != NULL)
                        {
                            *(void **)(localContextInfoPointer + 0x1720) = SubProcessTag;
                        }
                        if ((localObjectAttributesFlagsPointerData._0_8_ != 0) &&
                            ((localObjectAttributesFlagsPointerData & (PVOID)0x1) == (PVOID)0x0))
                        {
                            status = RtlAllocateActivationContextStack(&localContextStackHandle);
                            if (status < 0)
                            {
                                debugMessage =
                                    "SXS: %s - Failing thread create because RtlAllocateActivationContextStack() failed with status %08lx\n";
                            }
                            else
                            {
                                *(int64_t *)(localContextInfoPointer + 0x2c8) = localContextStackHandle;
                                localThreadStatus = status;
                                status = RtlActivateActivationContextEx(1, localContextInfoPointer, localObjectAttributesFlagsPointerData._0_8_, localObjectAttributesFlagsPointerData);
                                if (status >= 0)
                                {
                                    localThreadCreationFlags = 1;
                                    goto cleanup;
                                }
                                debugMessage =
                                    "SXS: %s - Failing thread create because RtlActivateActivationContextEx() failed with status %08lx\n";
                            }
                            localThreadStatus = status;
                            DbgPrint(debugMessage, "CreateRemoteThreadEx", status);
                            goto cleanup;
                        }
                    cleanup:
                        localThreadStatus = status;
                        if (DAT_18028cc84 != 0)
                        {
                            moduleHandle = GetModuleHandleA("csrsrv");
                            csrCreateRemoteThread = GetProcAddressForCaller(moduleHandle, "CsrCreateRemoteThread", returnAddress);
                            if ((csrCreateRemoteThread != NULL) &&
                                (status = ((NTSTATUS(NTAPI *)(HANDLE, PVOID))csrCreateRemoteThread)(localThreadHandlePointer, localThreadContextFlags), localThreadStatus = status, status < 0))
                                goto cleanup;
                        }
                    }
                    if (lpThreadId != NULL)
                    {
                        *lpThreadId = localThreadContextFlags._8_4_;
                    }
                    if ((localThreadCreationFlags != 0) && ((dwCreationFlags & 4) == 0))
                    {
                        NtResumeThread(localThreadHandlePointer, localObjectAttributesFlagsPointerDataPointer);
                    }
                }
            cleanup:
                if (localObjectAttributesFlagsPointerData._0_8_ != 0)
                {
                    RtlReleaseActivationContext();
                }
                if (localProcessHandle != NULL)
                {
                    NtClose();
                }
                if (status < 0)
                {
                    if ((localThreadCreationFlags != 0) && (localObjectAttributesFlagsPointerData._0_8_ != 0))
                    {
                        RtlReleaseActivationContext();
                    }
                    if (localContextStackHandle != 0)
                    {
                        RtlFreeActivationContextStack();
                    }
                    if (localThreadHandlePointer != 0)
                    {
                        NtTerminateThread(localThreadHandlePointer, status);
                        NtClose(localThreadHandlePointer);
                    }
                    ConvertAndSetLastError(status);
                    localThreadHandlePointer = 0;
                }
            }
        }
    }
    else
    {
        status = -0x3ffffff3;
    }

cleanup:
    ConvertAndSetLastError(status);
cleanup_2:
    __security_check_cookie(securityCookieCheck ^ (uint64_t)securityCookie);
    return threadHandle;
}
