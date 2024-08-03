HANDLE __stdcall CreateRemoteThread(HANDLE hProcess, LPS...)
180039b90 4c 8b dc        MOV        R11,RSP
180039b93 48 83 ec 48     SUB        RSP,0x48
180039b97 44 8b 54        MOV        R10D,dword ptr [RSP + dwCreationFlags]
          24 78
180039b9c 48 8b 84        MOV        RAX,qword ptr [RSP + lpThreadId]
          24 80 00 
          00 00
180039ba4 41 81 e2        AND        R10D,0x10004
          04 00 01 00
180039bab 49 89 43 f0     MOV        qword ptr [R11 + local_10],RAX
180039baf 49 83 63        AND        qword ptr [R11 + local_18],0x0
          e8 00
180039bb4 48 8b 44        MOV        RAX,qword ptr [RSP + lpParameter]
          24 70
180039bb9 45 89 53 e0     MOV        dword ptr [R11 + local_20],R10D
180039bbd 49 89 43 d8     MOV        qword ptr [R11 + local_28],RAX
180039bc1 48 ff 15        CALL       qword ptr [->API-MS-WIN-CORE-PROCESSTHREADS-L1] = 000abca6
          50 80 04 00
180039bc8 0f 1f 44        NOP        dword ptr [RAX + RAX*0x1]
          00 00
180039bcd 48 83 c4 48     ADD        RSP,0x48
180039bd1 c3              RET
180039bd2 cc              ??         CCh