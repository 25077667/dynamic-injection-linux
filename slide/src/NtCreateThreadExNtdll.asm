undefined8 __fastcall NtCreateThreadEx(void)
18009d5c0 4c 8b d1        MOV        R10,RCX
18009d5c3 b8 c1 00        MOV        EAX,0xc1
          00 00
18009d5c8 f6 04 25        TEST       byte ptr [DAT_7ffe0308],0x1
          08 03 fe 
          7f 01
18009d5d0 75 03           JNZ        LAB_18009d5d5
18009d5d2 0f 05           SYSCALL
18009d5d4 c3              RET
                        LAB_18009d5d5     XREF[1]:     18009d5d0(j)  
18009d5d5 cd 2e           INT        0x2e
18009d5d7 c3              RET
                        LAB_18009d5d8     XREF[1]:     180176bd4(*)  
18009d5d8 0f 1f 84        NOP        dword ptr [RAX + RAX*0x1]
          00 00 00 
          00 00
