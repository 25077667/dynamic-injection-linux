static inline int DuplicateAndQueryProcess(HANDLE *hProcess, HANDLE *duplicatedProcessHandle)
{
    int status;

    *duplicatedProcessHandle = NULL;
    status = NtDuplicateObject((HANDLE)-1, *hProcess, (HANDLE)-1, duplicatedProcessHandle);
    if (status >= 0)
    {
        *hProcess = *duplicatedProcessHandle;
        status = NtQueryInformationProcess(*hProcess, ProcessBasicInformation, NULL, 0, NULL);
        if (status >= 0 && NULL != ClientId.UniqueProcess)
        {
            status = NtQueryInformationProcess(*hProcess, ProcessWow64Information, NULL, 0, NULL);
            if (status >= 0 && 1 < ((int)NULL - 2U))
            {
                status = STATUS_INVALID_PARAMETER;
            }
        }
    }

    return status;
}

static inline int HandleActivationContext(char *contextFlag)
{
    int status;

    *contextFlag = 0;
    status = RtlQueryInformationActivationContext(1, NULL, NULL);
    if (status >= 0)
    {
        if (NULL != NULL || SubProcessTag != NULL || (((int64_t)NULL & 1) == 0))
        {
            *contextFlag = 1;
        }
    }

    return status;
}

static inline int CreateRemoteThreadHelper(
    HANDLE hProcess,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    SIZE_T dwStackSize,
    char contextFlag,
    HANDLE *localThreadHandle)
{
    int status;
    int64_t contextInfo = (uint64_t)(-(int64_t)((dwCreationFlags & 0x10000) != 0) & dwStackSize);
    uint64_t stackSize = (dwCreationFlags & 0x10000) ? 0 : dwStackSize;

    status = NtCreateThreadEx(localThreadHandle, 0x1FFFFF, NULL, hProcess, lpStartAddress, lpParameter, contextFlag, dwStackSize, stackSize, dwStackSize, NULL);
    return status;
}

int ManageActivationContextDuringThreadCreation(HANDLE localThreadHandle, char contextFlag, int *threadStatus)
{
    if (!contextFlag)
    {
        return *threadStatus;
    }

    if (SubProcessTag != NULL)
    {
        *(void **)((char *)&contextFlag + 0x1720) = SubProcessTag;
    }
    if (((int64_t)contextFlag & 1) != 0)
    {
        return *threadStatus;
    }

    *threadStatus = RtlAllocateActivationContextStack((int64_t *)&contextFlag);
    if (*threadStatus < 0)
    {
        DbgPrint("SXS: %s - Failing thread create because RtlAllocateActivationContextStack() failed with status %08lx\n",
                 "CreateRemoteThreadEx", *threadStatus);
        return *threadStatus;
    }

    *(int64_t *)((char *)&contextFlag + 0x2C8) = contextFlag;
    *threadStatus = RtlActivateActivationContextEx(1, (void *)&contextFlag, (int64_t)&contextFlag, NULL);
    if (*threadStatus < 0)
    {
        DbgPrint("SXS: %s - Failing thread create because RtlActivateActivationContextEx() failed with status %08lx\n",
                 "CreateRemoteThreadEx", *threadStatus);
        return *threadStatus;
    }
}

HANDLE __stdcall CreateRemoteThreadEx(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId)
{
    HANDLE threadHandle = NULL;
    HANDLE duplicatedProcessHandle = NULL;
    char contextFlag;
    int status;
    uint attributes[2] = {0};
    uint attributeFlags = 0x1c;
    uint64_t securityCookie = __security_cookie ^ (uint64_t)&securityCookie;

    if ((dwCreationFlags & 0xfffefffb) == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    status = BaseFormatObjectAttributes(attributes, 0, 0);
    if (status < 0)
    {
        goto cleanup;
    }

    if (lpAttributeList != NULL)
    {
        status = InitializeProcThreadAttributeList(lpAttributeList, 1, attributes);
        if (status < 0)
            goto cleanup;
    }

    if (hProcess != (HANDLE)-1)
    {
        status = DuplicateAndQueryProcess(&hProcess, &duplicatedProcessHandle);
        if (status < 0)
            goto cleanup;
    }

    status = HandleActivationContext(&contextFlag);
    if (status < 0)
    {
        goto cleanup;
    }

    status = CreateRemoteThreadHelper(hProcess, lpStartAddress, lpParameter, dwStackSize, contextFlag, &threadHandle);
    if (status >= 0)
    {
        status = ManageActivationContextDuringThreadCreation(threadHandle, contextFlag, &status);
        if (status < 0)
        {
            goto cleanup;
        }

        if (lpThreadId != NULL)
        {
            *lpThreadId = (DWORD)threadHandle;
        }
        if (contextFlag && !(dwCreationFlags & 4))
        {
            NtResumeThread(threadHandle, NULL);
        }
    }

cleanup:
    if ((int64_t)contextFlag != 0)
    {
        RtlReleaseActivationContext((int64_t)contextFlag);
    }
    if (duplicatedProcessHandle != NULL)
    {
        NtClose(duplicatedProcessHandle);
    }
    if (status < 0)
    {
        if (contextFlag && (int64_t)contextFlag != 0)
        {
            RtlReleaseActivationContext((int64_t)contextFlag);
        }
        if (contextFlag != 0)
        {
            RtlFreeActivationContextStack((int64_t)contextFlag);
        }
        if (threadHandle != 0)
        {
            NtTerminateThread(threadHandle, status);
            NtClose(threadHandle);
        }
        ConvertAndSetLastError(status);
        threadHandle = 0;
    }

    ConvertAndSetLastError(status);
    __security_check_cookie(securityCookie ^ (uint64_t)&securityCookie);
    return threadHandle;
}
