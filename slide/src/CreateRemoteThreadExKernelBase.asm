
HANDLE __stdcall CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
18002dad0 4c 8b dc        MOV        R11,RSP
18002dadb 48 81 ec        SUB        RSP,0x570
          70 05 00 00
18002dae9 48 33 c4        XOR        RAX,RSP
18002db0f 48 89 84        MOV        qword ptr [RSP + local_4a0],RAX
          24 f8 00 
          00 00
18002db29 88 8c 24        MOV        byte ptr [RSP + local_4f7],hProcess
          a1 00 00 00
18002db33 0f 11 84        MOVUPS     xmmword ptr [RSP + local_4d8[0]],XMM0
          24 c0 00 
          00 00
18002db3b 49 89 8b        MOV        qword ptr [R11 + local_4c8],hProcess
          38 fb ff ff
18002db45 0f 11 8c        MOVUPS     xmmword ptr [RSP + local_488[0]],XMM1
          24 10 01 
          00 00
18002db4d 88 8c 24        MOV        byte ptr [RSP + local_4f8],hProcess
          a0 00 00 00
18002db54 49 89 8b        MOV        qword ptr [R11 + local_4f0],hProcess
          10 fb ff ff
18002db5b f7 84 24        TEST       dword ptr [RSP + dwCreationFlags],0xfffefffb
          c8 05 00 
          00 fb ff 
18002db66 0f 85 74        JNZ        LAB_1800a32e0
          57 07 00
18002db76 49 8d 8b        LEA        hProcess=>local_3f8,[R11 + -0x3f8]
          08 fc ff ff
18002db7d e8 de c5        CALL       BaseFormatObjectAttributes                       undefined BaseFormatObjectAttrib
          ff ff
18002db8c 85 c0           TEST       EAX,EAX
18002db8e 0f 88 6d        JS         LAB_1800a3301
          57 07 00
18002db94 48 c7 84        MOV        qword ptr [RSP + local_3c0],0x10003
          24 d8 01 
          00 00 03 
18002dba0 48 c7 84        MOV        qword ptr [RSP + local_3b8],0x10
          24 e0 01 
          00 00 10 
18002dbac 4c 89 8c        MOV        qword ptr [RSP + local_3a8],lpStartAddress
          24 f0 01 
          00 00
18002dbb4 48 8d 84        LEA        RAX=>local_488,[RSP + 0x110]
          24 10 01 
          00 00
18002dbc4 48 c7 84        MOV        qword ptr [RSP + local_3a0],0x10004
          24 f8 01 
          00 00 04 
18002dbd0 48 c7 84        MOV        qword ptr [RSP + local_398],0x8
          24 00 02 
          00 00 08 
18002dbdc 4c 89 8c        MOV        qword ptr [RSP + local_388],lpStartAddress
          24 10 02 
          00 00
18002dbe4 48 8d 84        LEA        RAX=>local_4b8,[RSP + 0xe0]
          24 e0 00 
          00 00
18002dbf4 c7 84 24        MOV        dword ptr [RSP + local_4e8],0x2
          b0 00 00 
          00 02 00 
18002dbff 48 85 db        TEST       RBX,RBX
18002dc02 0f 85 fd        JNZ        LAB_1800a3305
          56 07 00
                      LAB_18002dc08                                   XREF[1]:     1800a3398(j)  
18002dc08 8b 84 24        MOV        EAX,dword ptr [RSP + local_4e8]
          b0 00 00 00
18002dc0f 48 c1 e0 05     SHL        RAX,0x5
18002dc13 48 83 c0 08     ADD        RAX,0x8
18002dc27 41 81 e7        AND        R15D,0x10000
          00 00 01 00
18002dc2e 4c 89 8c        MOV        qword ptr [RSP + local_4e0],lpStartAddress
          24 b8 00 
          00 00
18002dc36 40 b6 01        MOV        SIL,0x1
18002dc3d 4c 3b f1        CMP        R14,hProcess
18002dc40 0f 85 57        JNZ        LAB_1800a339d
          57 07 00
18002dc49 0f 84 97        JZ         LAB_18002dce6
          00 00 00
18002dc4f 4c 89 4c        MOV        qword ptr [RSP + local_568],lpStartAddress
          24 30
18002dc54 48 c7 44        MOV        qword ptr [RSP + local_570],0x10
          24 28 10 
          00 00 00
18002dc5d 48 8d 84        LEA        RAX=>local_4d8,[RSP + 0xc0]
          24 c0 00 
          00 00
18002dc78 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlQueryInformationAct]   = 00287378
          59 1c 19 00
18002dc90 85 c0           TEST       EAX,EAX
18002dc92 0f 88 73        JS         LAB_18002df0b
          02 00 00
18002dc98 44 38 0d        CMP        byte ptr [DAT_18028cc84],lpStartAddress
          e5 ef 25 00
18002dcaa 4c 39 88        CMP        qword ptr [RAX + offset SubProcessTag],lpStart   = 00000000
          20 17 00 00
18002dcb3 4c 39 8c        CMP        qword ptr [RSP + local_4d8[0]],lpStartAddress
          24 c0 00 
          00 00
                      LAB_18002dcbd                                   XREF[1]:     18002dcdc(j)  
18002dcbd 44 88 8c        MOV        byte ptr [RSP + local_4f8],lpStartAddress
          24 a0 00 
          00 00
                      LAB_18002dcc5                                   XREF[1]:     18002dcee(j)  
18002dcc5 f6 84 24        TEST       byte ptr [RSP + dwCreationFlags],0x4
          c8 05 00 
          00 04
18002dccd 41 8b d1        MOV        lpThreadAttributes,lpStartAddress
18002dcd0 75 1e           JNZ        LAB_18002dcf0
                      LAB_18002dcd4                                   XREF[1]:     18002dcbb(j)  
18002dcd4 f6 84 24        TEST       byte ptr [RSP + local_4d8[8]],0x1
          c8 00 00 
          00 01
18002dcdc 75 df           JNZ        LAB_18002dcbd
                      LAB_18002dcde                                   XREF[2]:     18002dc9f(j), 18002dcb1(j)  
18002dcde c6 84 24        MOV        byte ptr [RSP + local_4f8],0x1
          a0 00 00 
          00 01
                      LAB_18002dce6                                   XREF[1]:     18002dc49(j)  
18002dce6 44 38 8c        CMP        byte ptr [RSP + local_4f8],lpStartAddress
          24 a0 00 
          00 00
18002dcee 74 d5           JZ         LAB_18002dcc5
                      LAB_18002dcf0                                   XREF[1]:     18002dcd0(j)  
18002dcf0 ba 01 00        MOV        lpThreadAttributes,0x1
          00 00
                      LAB_18002dcf5                                   XREF[1]:     18002dcd2(j)  
18002dcf5 89 94 24        MOV        dword ptr [RSP + local_4c0],lpThreadAttributes
          d8 00 00 00
18002dcff f7 d8           NEG        EAX
18002dd01 48 1b c9        SBB        hProcess,hProcess
18002dd0c 48 23 c8        AND        hProcess,RAX
18002dd0f 45 85 ff        TEST       R15D,R15D
18002dd12 49 0f 45 c1     CMOVNZ     RAX,lpStartAddress
18002dd16 4c 8d 84        LEA        dwStackSize=>local_3c8,[RSP + 0x1d0]
          24 d0 01 
          00 00
18002dd2d 4c 89 4c        MOV        qword ptr [RSP + local_560],lpStartAddress
          24 38
18002dd32 89 54 24 30     MOV        dword ptr [RSP + local_568],lpThreadAttributes
18002dd3e 48 89 44        MOV        qword ptr [RSP + local_570],RAX
          24 28
18002dd4b 48 89 44        MOV        qword ptr [RSP + local_578],RAX
          24 20
18002dd60 48 8d 8c        LEA        hProcess=>local_4f0,[RSP + 0xa8]
          24 a8 00 
          00 00
18002dd68 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtCreateThreadEx]        = 002895ce
          f9 26 19 00
18002dd7f 85 c0           TEST       EAX,EAX
18002dd81 0f 88 be        JS         LAB_18002df45
          01 00 00
18002dd87 40 38 b4        CMP        byte ptr [RSP + local_4f8],SIL
          24 a0 00 
          00 00
18002dd8f 75 4e           JNZ        LAB_18002dddf
                      LAB_18002dd91                                   XREF[3]:     18002de28(j), 18002de54(j), 
                                                                                   18002de81(j)  
18002dd91 4d 85 ed        TEST       R13,R13
18002dd94 74 0c           JZ         LAB_18002dda2
18002dd9e 41 89 45 00     MOV        dword ptr [R13],EAX
                      LAB_18002dda2                                   XREF[1]:     18002dd94(j)  
18002dda2 40 38 b4        CMP        byte ptr [RSP + local_4f8],SIL
          24 a0 00 
          00 00
18002ddb0 f6 84 24        TEST       byte ptr [RSP + dwCreationFlags],0x4
          c8 05 00 
          00 04
18002ddb8 0f 85 87        JNZ        LAB_18002df45
          01 00 00
18002ddbe 48 8d 94        LEA        lpThreadAttributes=>local_4b0,[RSP + 0xe8]
          24 e8 00 
          00 00
18002ddce 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtResumeThread]          = 00289628
          ab 26 19 00
18002dde8 48 39 b0        CMP        qword ptr [RAX + offset SubProcessTag],RSI       = 00000000
          20 17 00 00
18002ddef 74 1f           JZ         LAB_18002de10
18002de09 48 89 88        MOV        qword ptr [RAX + 0x1720],hProcess
          20 17 00 00
                      LAB_18002de10                                   XREF[1]:     18002ddef(j)  
18002de10 48 39 b4        CMP        qword ptr [RSP + local_4d8[0]],RSI
          24 c0 00 
          00 00
                      LAB_18002de21                                   XREF[1]:     18002df06(j)  
18002de21 40 38 35        CMP        byte ptr [DAT_18028cc84],SIL
          5c ee 25 00
18002de28 0f 84 63        JZ         LAB_18002dd91
          ff ff ff
18002de35 e8 b6 d7        CALL       GetModuleHandleA                                 HMODULE GetModuleHandleA(LPCSTR 
          ff ff
18002de4c e8 6f 3e        CALL       GetProcAddressForCaller                          undefined GetProcAddressForCalle
          03 00
18002de51 48 85 c0        TEST       RAX,RAX
18002de5a 48 8d 94        LEA        lpThreadAttributes=>local_488,[RSP + 0x110]
          24 10 01 
          00 00
18002de6a ff 15 a0        CALL       qword ptr [->_guard_dispatch_icall]              undefined _guard_dispatch_icall()
          2a 19 00                                                                    = 180092160
18002de79 85 c0           TEST       EAX,EAX
18002de7b 0f 88 c4        JS         LAB_18002df45
          00 00 00
                      LAB_18002de86                                   XREF[1]:     18002de18(j)  
18002de86 f6 84 24        TEST       byte ptr [RSP + local_4d8[8]],0x1
          c8 00 00 
          00 01
18002de8e 75 8a           JNZ        LAB_18002de1a
18002de90 48 8d 8c        LEA        hProcess=>local_4c8,[RSP + 0xd0]
          24 d0 00 
          00 00
18002de98 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlAllocateActivationC]   = 002895e2
          d1 25 19 00
18002dead 85 c0           TEST       EAX,EAX
18002deaf 78 74           JS         LAB_18002df25
18002dec1 48 89 88        MOV        qword ptr [RAX + 0x2c8],hProcess
          c8 02 00 00
18002dec8 4c 8d 8c        LEA        lpStartAddress=>local_478,[RSP + 0x120]
          24 20 01 
          00 00
18002dee5 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlActivateActivationC]   = 00289606
          8c 25 19 00
18002defa 85 c0           TEST       EAX,EAX
18002defc 78 30           JS         LAB_18002df2e
18002defe c6 84 24        MOV        byte ptr [RSP + local_4f7],0x1
          a1 00 00 
          00 01
18002df1c e8 93 06        CALL       NTDLL.DLL::DbgPrint                              undefined DbgPrint()
          06 00
                      LAB_18002df25                                   XREF[1]:     18002deaf(j)  
18002df25 48 8d 0d        LEA        hProcess,[s_SXS:_%s_-_Failing_thread_create_b_]   = "SXS: %s - Failing thread crea
          64 30 23 00
                      LAB_18002df2e                                   XREF[1]:     18002defc(j)  
18002df2e 48 8d 0d        LEA        hProcess,[s_SXS:_%s_-_Failing_thread_create_b_]  = "SXS: %s - Failing thread crea
          eb 2f 23 00
18002df3f e8 70 06        CALL       NTDLL.DLL::DbgPrint                              undefined DbgPrint()
          06 00
                      LAB_18002df45                                   XREF[6]:     18002dd81(j), 18002ddaa(j), 
                                                                                   18002ddb8(j), 18002ddda(j), 
                                                                                   18002de7b(j), 18002df23(j)  
18002df45 48 8b 8c        MOV        hProcess,qword ptr [RSP + local_4d8[0]]
          24 c0 00 
          00 00
18002df4d 48 85 c9        TEST       hProcess,hProcess
18002df50 75 42           JNZ        LAB_18002df94
18002df5a 48 85 c9        TEST       hProcess,hProcess
18002df5d 0f 85 38        JNZ        LAB_1800a349b
          55 07 00
                      LAB_18002df63                                   XREF[1]:     1800a34a8(j)  
18002df63 85 db           TEST       EBX,EBX
18002df65 0f 88 42        JS         LAB_1800a34ad
          55 07 00
                      LAB_18002df73                                   XREF[1]:     1800a32fc(j)  
18002df73 48 8b 8c        MOV        hProcess,qword ptr [RSP + local_38]
          24 60 05 
          00 00
18002df7b 48 33 cc        XOR        hProcess,RSP
18002df7e e8 bd 01        CALL       __security_check_cookie
          06 00
18002df92 c3              RET
                      LAB_18002df94                                   XREF[1]:     18002df50(j)  
18002df94 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlReleaseActivationCo]   = 002873ae
          4d 19 19 00
                      LAB_1800a32e0                                   XREF[2]:     18002db66(j), 180297c98(*)  
1800a32e0 b9 0d 00        MOV        hProcess,0xc000000d
          00 c0
1800a32e5 eb 0e           JMP        LAB_1800a32f5
                      LAB_1800a32e7                                   XREF[1]:     1800a3496(j)  
1800a32e7 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtClose]                 = 002861fc
          02 c7 11 00
                      LAB_1800a32f5                                   XREF[2]:     1800a32e5(j), 1800a3303(j)  
1800a32f5 e8 26 09        CALL       FUN_180023c20                                    undefined FUN_180023c20()
          f8 ff
                      LAB_1800a3305                                   XREF[1]:     18002dc02(j)  
1800a3305 c7 84 24        MOV        dword ptr [RSP + local_500],0x1c
          98 00 00 
          00 1c 00 
1800a3310 48 8d 84        LEA        RAX=>local_4e8,[RSP + 0xb0]
          24 b0 00 
          00 00
1800a3320 48 8d 84        LEA        RAX=>local_3c8,[RSP + 0x1d0]
          24 d0 01 
          00 00
1800a3330 4c 89 8c        MOV        qword ptr [RSP + local_518],lpStartAddress
          24 80 00 
          00 00
1800a3338 4c 89 4c        MOV        qword ptr [RSP + local_520],lpStartAddress
          24 78
1800a333d 4c 89 4c        MOV        qword ptr [RSP + local_528],lpStartAddress
          24 70
1800a3342 4c 89 4c        MOV        qword ptr [RSP + local_530],lpStartAddress
          24 68
1800a3347 4c 89 4c        MOV        qword ptr [RSP + local_538],lpStartAddress
          24 60
1800a334c 4c 89 4c        MOV        qword ptr [RSP + local_540],lpStartAddress
          24 58
1800a3351 4c 89 4c        MOV        qword ptr [RSP + local_548],lpStartAddress
          24 50
1800a3356 4c 89 4c        MOV        qword ptr [RSP + local_550],lpStartAddress
          24 48
1800a335b 4c 89 4c        MOV        qword ptr [RSP + local_558],lpStartAddress
          24 40
1800a3360 4c 89 4c        MOV        qword ptr [RSP + local_560],lpStartAddress
          24 38
1800a3365 4c 89 4c        MOV        qword ptr [RSP + local_568],lpStartAddress
          24 30
1800a336a 4c 89 4c        MOV        qword ptr [RSP + local_570],lpStartAddress
          24 28
1800a336f 4c 89 4c        MOV        qword ptr [RSP + local_578],lpStartAddress
          24 20
1800a3374 4c 8d 84        LEA        dwStackSize=>local_4c0,[RSP + 0xd8]
          24 d8 00 
          00 00
1800a3381 e8 1a b9        CALL       FUN_18006eca0
          fc ff
1800a3390 85 c0           TEST       EAX,EAX
1800a3392 0f 88 69        JS         LAB_1800a3301
          ff ff ff
                      LAB_1800a339d                                   XREF[1]:     18002dc40(j)  
1800a339d 44 89 4c        MOV        dword ptr [RSP + local_568],lpStartAddress
          24 30
1800a33a2 44 89 4c        MOV        dword ptr [RSP + local_570],lpStartAddress
          24 28
1800a33a7 c7 44 24        MOV        dword ptr [RSP + local_578],0x402
          20 02 04 
          00 00
1800a33af 4c 8d 8c        LEA        lpStartAddress=>local_4e0,[RSP + 0xb8]
          24 b8 00 
          00 00
1800a33bd 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtDuplicateObject]       = 002876da
          94 c6 11 00
1800a33cb 85 c0           TEST       EAX,EAX
1800a33cd 4c 0f 49        CMOVNS     R14,qword ptr [RSP + local_4e0]
          b4 24 b8 
          00 00 00
1800a33d6 48 89 4c        MOV        qword ptr [RSP + local_578],hProcess
          24 20
1800a33df 4c 8d 84        LEA        dwStackSize=>local_470,[RSP + 0x128]
          24 28 01 
          00 00
1800a33ec 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtQueryInformationProc]   = 00286138
          35 c6 11 00
1800a3404 85 c0           TEST       EAX,EAX
1800a3419 48 3b 41 40     CMP        RAX,qword ptr [hProcess + offset ClientId]
1800a341d 75 09           JNZ        LAB_1800a3428
                      LAB_1800a3428                                   XREF[1]:     1800a341d(j)  
1800a3428 41 8a f1        MOV        SIL,lpStartAddress
1800a342b 4c 89 4c        MOV        qword ptr [RSP + local_578],lpStartAddress
          24 20
1800a3436 4c 8d 84        LEA        dwStackSize=>local_438,[RSP + 0x160]
          24 60 01 
          00 00
1800a3445 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtQueryInformationProc]   = 00286138
          dc c5 11 00
1800a345d 85 c0           TEST       EAX,EAX
1800a3468 83 c0 fe        ADD        EAX,-0x2
1800a3473 0f 47 d9        CMOVA      EBX,hProcess
                      LAB_1800a347d                                   XREF[3]:     1800a3406(j), 1800a3426(j), 
                                                                                   1800a345f(j)  
1800a347d 85 db           TEST       EBX,EBX
1800a347f 0f 89 c1        JNS        LAB_18002dc46
          a7 f8 ff
1800a348d 48 85 c9        TEST       hProcess,hProcess
1800a3490 0f 84 5d        JZ         LAB_1800a32f3
          fe ff ff
                      LAB_1800a349b                                   XREF[1]:     18002df5d(j)  
1800a349b 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtClose]                 = 002861fc
          4e c5 11 00
                      LAB_1800a34ad                                   XREF[1]:     18002df65(j)  
1800a34ad 40 38 b4        CMP        byte ptr [RSP + local_4f7],SIL
          24 a1 00 
          00 00
1800a34bf 48 85 c9        TEST       hProcess,hProcess
1800a34c2 74 0c           JZ         LAB_1800a34d0
1800a34c4 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlReleaseActivationCo]   = 002873ae
          1d c4 11 00
1800a34d8 48 85 c9        TEST       hProcess,hProcess
1800a34db 74 0c           JZ         LAB_1800a34e9
1800a34dd 48 ff 15        CALL       qword ptr [->NTDLL.DLL::RtlFreeActivationConte]   = 0028963a
          a4 cf 11 00
1800a34f1 48 85 c9        TEST       hProcess,hProcess
1800a34f4 74 22           JZ         LAB_1800a3518
1800a34f8 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtTerminateThread]       = 0028965a
          91 cf 11 00
1800a350c 48 ff 15        CALL       qword ptr [->NTDLL.DLL::NtClose]                 = 002861fc
          dd c4 11 00
1800a351a e8 01 07        CALL       FUN_180023c20                                    undefined FUN_180023c20()
          f8 ff
1800a351f 48 89 b4        MOV        qword ptr [RSP + local_4f0],RSI
          24 a8 00 
          00 00
