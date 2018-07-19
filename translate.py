#shld
SHLD = "POP eax; 
# 
# rule shld
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        EDX, DWORD PTR [EBP + 0x4]
#     MOV        CL, BYTE PTR [EBP + 0x8]
#     INC        EBP
#     SHLD       EAX, EDX, CL
#     MOV        DWORD PTR [EBP + 0x4], EAX
#     PUSHFD
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8b 55 04 [0-40] 8a 4d 08 [0-40] 45 [0-40] 0f a5 d0 [0-40] 89 45 04 [0-40] 9c [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_read_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        AX, WORD PTR [EAX + EBP]
#     SUB        EBP, 0x2
#     MOV        WORD PTR [EBP], AX
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 66 8b 44 05 00 [0-40] 83 ed 02 [0-40] 66 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_write_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        DL, BYTE PTR [EBP + 0x4]
#     ADD        EBP, 0x5
#     MOV        BYTE PTR [EAX], DL
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8a 55 04 [0-40] 83 c5 05 [0-40] 88 10 }
#
#
#     condition:
#         all of them
# }
# rule d_read_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        EAX, DWORD PTR [EAX]
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8b 00 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_shl
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AL, BYTE PTR [EBP]
#     SHL        AL, CL
#     MOV        BYTE PTR [EBP], AL
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8a 45 00 [0-40] d2 e0 [0-40] 88 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule pop_stack_top_base
# {
#     /*
#     MOV        EBP, DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8b 6d 00 }
#
#
#     condition:
#         all of them
# }
# rule d_push_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        EAX, DWORD PTR [EAX + EDI]
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 8b 04 07 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_shr
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AL, BYTE PTR [EBP]
#     SHR        AL, CL
#     MOV        BYTE PTR [EBP], AL
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8a 45 00 [0-40] d2 e8 [0-40] 88 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_nand
# {
#     /*
#     MOV        AX, WORD PTR [EBP]
#     NOT        AX
#     ADD        EBP, 0x2
#     MOV        DX, WORD PTR [EBP]
#     NOT        DX
#     AND        AX, DX
#     MOV        WORD PTR [EBP], AX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 66 8b 45 00 [0-40] 66 f7 d0 [0-40] 83 c5 02 [0-40] 66 8b 55 00 [0-40] 66 f7 d2 [0-40] 66 23 c2 [0-40] 66 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_shr
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AX, WORD PTR [EBP]
#     SHR        AX, CL
#     MOV        WORD PTR [EBP], AX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 66 8b 45 00 [0-40] 66 d3 e8 [0-40] 66 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_push_imm
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     DEC        EBP
#     MOV        BYTE PTR [EBP], AL
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 4d [0-40] 88 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_shl
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        EAX, DWORD PTR [EBP]
#     SHL        EAX, CL
#     MOV        DWORD PTR [EBP], EAX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8b 45 00 [0-40] d3 e0 [0-40] 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_write_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        DL, BYTE PTR [EBP]
#     MOV        BYTE PTR [EAX + EBP], DL
#     INC        EBP
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 8a 55 00 [0-40] 88 54 05 00 [0-40] 45 }
#
#
#     condition:
#         all of them
# }
# rule d_ror
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        EAX, DWORD PTR [EBP]
#     ROR        EAX, CL
#     MOV        DWORD PTR [EBP], EAX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8b 45 00 [0-40] d3 c8 [0-40] 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule push_stack_top_base
# {
#     /*
#     MOV        EAX, EBP
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8b c5 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_rol
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AX, WORD PTR [EBP]
#     ROL        AX, CL
#     MOV        WORD PTR [EBP], AX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 66 8b 45 00 [0-40] 66 d3 c0 [0-40] 66 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_write_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        EDX, DWORD PTR [EBP + 0x4]
#     ADD        EBP, 0x8
#     MOV        DWORD PTR [EAX], EDX
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8b 55 04 [0-40] 83 c5 08 [0-40] 89 10 }
#
#
#     condition:
#         all of them
# }
# rule b_push_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        AL, BYTE PTR [EAX + EDI]
#     DEC        EBP
#     MOV        BYTE PTR [EBP], AL
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 8a 04 07 [0-40] 4d [0-40] 88 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_read_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     ADD        EBP, 0x3
#     MOV        AL, BYTE PTR [EAX]
#     MOV        BYTE PTR [EBP], AL
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 83 c5 03 [0-40] 8a 00 [0-40] 88 45 00 }
#
#
#     condition:
#         all of them
# }
# rule check_stack
# {
#     /*
#     LEA        EAX, DWORD PTR [EDI + 0x64]
#     CMP        EBP, EAX
#     LEA        ECX, DWORD PTR [EDI + 0x64]
#     SUB        ECX, EDI
#     LEA        EAX, DWORD PTR [EBP + 0xFFFFFF38]
#     AND        AL, 0xFC
#     MOV        ESP, EAX
#     PUSH       ESI
#     MOV        ESI, EDI
#     MOV        EDI, EAX
#     MOV        EDX, ECX
#     CLD
#     REPE MOVSB
#     SUB        EDI, EDX
#     POP        ESI
#     */
#     strings:
#         $hex_1 = { 8d 47 64 [0-40] 3b e8 [0-40] 8d 4f 64 [0-40] 2b cf [0-40] 8d 85 38 ff ff ff [0-40] 24 fc [0-40] 8b e0 [0-40] 56 [0-40] 8b f7 [0-40] 8b f8 [0-40] 8b d1 [0-40] fc [0-40] f3 a4 [0-40] 2b fa [0-40] 5e }
#
#
#     condition:
#         all of them
# }
# rule d_shr
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        EAX, DWORD PTR [EBP]
#     SHR        EAX, CL
#     MOV        DWORD PTR [EBP], EAX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8b 45 00 [0-40] d3 e8 [0-40] 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_nand
# {
#     /*
#     MOV        AL, BYTE PTR [EBP]
#     NOT        AL
#     INC        EBP
#     MOV        DL, BYTE PTR [EBP]
#     NOT        DL
#     AND        AL, DL
#     MOV        BYTE PTR [EBP], AL
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 45 00 [0-40] f6 d0 [0-40] 45 [0-40] 8a 55 00 [0-40] f6 d2 [0-40] 22 c2 [0-40] 88 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_nand
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     NOT        EAX
#     ADD        EBP, 0x4
#     MOV        EDX, DWORD PTR [EBP]
#     NOT        EDX
#     AND        EAX, EDX
#     MOV        DWORD PTR [EBP], EAX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] f7 d0 [0-40] 83 c5 04 [0-40] 8b 55 00 [0-40] f7 d2 [0-40] 23 c2 [0-40] 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule run_stack
# {
#     /*
#     MOV        AL, BYTE PTR [EBP]
#     MOVZX      EAX, AL
#     INC        EBP
#     MOV        EDX, EBP
#     ADD        EBP, EAX
#     CALL       EDX
#     */
#     strings:
#         $hex_1 = { 8a 45 00 [0-40] 0f b6 c0 [0-40] 45 [0-40] 8b d5 [0-40] 03 e8 [0-40] ff d2 }
#
#
#     condition:
#         all of them
# }
# rule b_push_imm_zx
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_pop_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        DL, BYTE PTR [EBP]
#     MOV        BYTE PTR [EAX + EDI], DL
#     INC        EBP
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 8a 55 00 [0-40] 88 14 07 [0-40] 45 }
#
#
#     condition:
#         all of them
# }
# rule cpuid
# {
#     /*
#     CPUID
#     SUB        EBP, 0x10
#     MOV        DWORD PTR [EBP + 0xC], EAX
#     MOV        DWORD PTR [EBP + 0x8], EBX
#     MOV        DWORD PTR [EBP + 0x4], ECX
#     MOV        DWORD PTR [EBP], EDX
#     */
#     strings:
#         $hex_1 = { 0f a2 [0-40] 83 ed 10 [0-40] 89 45 0c [0-40] 89 5d 08 [0-40] 89 4d 04 [0-40] 89 55 00 }
#
#
#     condition:
#         all of them
# }
# rule w_ror
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AX, WORD PTR [EBP]
#     ROR        AX, CL
#     MOV        WORD PTR [EBP], AX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 66 8b 45 00 [0-40] 66 d3 c8 [0-40] 66 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_shl
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AX, WORD PTR [EBP]
#     SHL        AX, CL
#     MOV        WORD PTR [EBP], AX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 66 8b 45 00 [0-40] 66 d3 e0 [0-40] 66 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_write_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        DX, WORD PTR [EBP]
#     MOV        WORD PTR [EAX + EBP], DX
#     ADD        EBP, 0x2
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 66 8b 55 00 [0-40] 66 89 54 05 00 [0-40] 83 c5 02 }
#
#
#     condition:
#         all of them
# }
# rule b_read_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        AL, BYTE PTR [EAX + EBP]
#     SUB        EBP, 0x1
#     MOV        BYTE PTR [EBP], AL
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 8a 04 28 [0-40] 83 ed 01 [0-40] 88 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_rol
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        EAX, DWORD PTR [EBP]
#     ROL        EAX, CL
#     MOV        DWORD PTR [EBP], EAX
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8b 45 00 [0-40] d3 c0 [0-40] 89 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule rdtsc
# {
#     /*
#     RDTSC
#     SUB        EBP, 0x8
#     MOV        DWORD PTR [EBP], EDX
#     MOV        DWORD PTR [EBP + 0x4], EAX
#     */
#     strings:
#         $hex_1 = { 0f 31 [0-40] 83 ed 08 [0-40] 89 55 00 [0-40] 89 45 04 }
#
#
#     condition:
#         all of them
# }
# rule nop
# {
#
#     strings:
#         $hex_1 = { ?? }
#
#
#     condition:
#         all of them
# }
# rule w_read_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     ADD        EBP, 0x2
#     MOV        AX, WORD PTR [EAX]
#     MOV        WORD PTR [EBP], AX
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 83 c5 02 [0-40] 66 8b 00 [0-40] 66 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_pop_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        DX, WORD PTR [EBP]
#     MOV        WORD PTR [EAX + EDI], DX
#     ADD        EBP, 0x2
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 66 8b 55 00 [0-40] 66 89 14 07 [0-40] 83 c5 02 }
#
#
#     condition:
#         all of them
# }
# rule w_add
# {
#     /*
#     MOV        AX, WORD PTR [EBP]
#     ADD        WORD PTR [EBP + 0x2], AX
#     PUSHFD
#     SUB        EBP, 0x2
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 66 8b 45 00 [0-40] 66 01 45 02 [0-40] 9c [0-40] 83 ed 02 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_write_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        EDX, DWORD PTR [EBP]
#     MOV        DWORD PTR [EAX + EBP], EDX
#     ADD        EBP, 0x4
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 8b 55 00 [0-40] 89 54 05 00 [0-40] 83 c5 04 }
#
#
#     condition:
#         all of them
# }
# rule dispatch
# {
#     /*
#     SUB        EBP, 0x2
#     FWAIT
#     FNSTSW     AX
#     MOV        WORD PTR [EBP], AX
#     */
#     strings:
#         $hex_1 = { 83 ed 02 [0-40] 9b [0-40] df e0 [0-40] 66 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_push_imm_zx
# {
#     /*
#     MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
#     SUB        ESI, 0x2
#     MOVZX      EAX, AX
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 66 8b 46 fe [0-40] 83 ee 02 [0-40] 0f b7 c0 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_push_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        AX, WORD PTR [EAX + EDI]
#     SUB        EBP, 0x2
#     MOV        WORD PTR [EBP], AX
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 66 8b 04 07 [0-40] 83 ed 02 [0-40] 66 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_add
# {
#     /*
#     MOV        AL, BYTE PTR [EBP]
#     ADD        BYTE PTR [EBP + 0x1], AL
#     PUSHFD
#     SUB        EBP, 0x3
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 45 00 [0-40] 00 45 01 [0-40] 9c [0-40] 83 ed 03 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_rol
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AL, BYTE PTR [EBP]
#     ROL        AL, CL
#     MOV        BYTE PTR [EBP], AL
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8a 45 00 [0-40] d2 c0 [0-40] 88 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule shrd
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        EDX, DWORD PTR [EBP + 0x4]
#     MOV        CL, BYTE PTR [EBP + 0x8]
#     INC        EBP
#     SHRD       EAX, EDX, CL
#     MOV        DWORD PTR [EBP + 0x4], EAX
#     PUSHFD
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8b 55 04 [0-40] 8a 4d 08 [0-40] 45 [0-40] 0f ad d0 [0-40] 89 45 04 [0-40] 9c [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule d_push_imm
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_push_imm
# {
#     /*
#     MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
#     SUB        ESI, 0x2
#     SUB        EBP, 0x2
#     MOV        WORD PTR [EBP], AX
#     */
#     strings:
#         $hex_1 = { 66 8b 46 fe [0-40] 83 ee 02 [0-40] 83 ed 02 [0-40] 66 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule set_key
# {
#     /*
#     MOV        EBX, DWORD PTR [EBP]
#     ADD        EBP, 0x4
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        ESI, EAX
#     ADD        EBP, 0x4
#     */
#     strings:
#         $hex_1 = { 8b 5d 00 [0-40] 83 c5 04 [0-40] 8b 45 00 [0-40] 8b f0 [0-40] 83 c5 04 }
#
#
#     condition:
#         all of them
# }
# rule d_add
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     ADD        DWORD PTR [EBP + 0x4], EAX
#     PUSHFD
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 01 45 04 [0-40] 9c [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule ret
# {
#     /*
#     MOV        ESP, EBP
#     POP        EDI
#     POP        ESI
#     POP        EBP
#     POP        EBX
#     POP        EDX
#     POP        ECX
#     POP        EAX
#     POPFD
#     RET
#     */
#     strings:
#         $hex_1 = { 8b e5 [0-40] 5f [0-40] 5e [0-40] 5d [0-40] 5b [0-40] 5a [0-40] 59 [0-40] 58 [0-40] 9d [0-40] c3 }
#
#
#     condition:
#         all of them
# }
# rule w_write_mem
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        DX, WORD PTR [EBP + 0x4]
#     ADD        EBP, 0x6
#     MOV        WORD PTR [EAX], DX
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 66 8b 55 04 [0-40] 83 c5 06 [0-40] 66 89 10 }
#
#
#     condition:
#         all of them
# }
# rule d_pop_reg
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVZX      EAX, AL
#     MOV        EDX, DWORD PTR [EBP]
#     MOV        DWORD PTR [EAX + EDI], EDX
#     ADD        EBP, 0x4
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f b6 c0 [0-40] 8b 55 00 [0-40] 89 14 07 [0-40] 83 c5 04 }
#
#
#     condition:
#         all of them
# }
# rule set_pc
# {
#     /*
#     MOV        EAX, DWORD PTR [EBP]
#     MOV        ESI, EAX
#     ADD        EBP, 0x4
#     */
#     strings:
#         $hex_1 = { 8b 45 00 [0-40] 8b f0 [0-40] 83 c5 04 }
#
#
#     condition:
#         all of them
# }
# rule d_read_stack
# {
#     /*
#     MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
#     SUB        ESI, 0x4
#     MOV        EAX, DWORD PTR [EAX + EBP]
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8b 46 fc [0-40] 83 ee 04 [0-40] 8b 44 05 00 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule w_push_imm_sx
# {
#     /*
#     MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
#     SUB        ESI, 0x2
#     MOVSX      EAX, AX
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 66 8b 46 fe [0-40] 83 ee 02 [0-40] 0f bf c0 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_ror
# {
#     /*
#     MOV        CL, BYTE PTR [EBP]
#     INC        EBP
#     MOV        AL, BYTE PTR [EBP]
#     ROR        AL, CL
#     MOV        BYTE PTR [EBP], AL
#     PUSHFD
#     SUB        EBP, 0x4
#     POP        DWORD PTR [EBP]
#     */
#     strings:
#         $hex_1 = { 8a 4d 00 [0-40] 45 [0-40] 8a 45 00 [0-40] d2 c8 [0-40] 88 45 00 [0-40] 9c [0-40] 83 ed 04 [0-40] 8f 45 00 }
#
#
#     condition:
#         all of them
# }
# rule b_push_imm_sx
# {
#     /*
#     MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
#     DEC        ESI
#     MOVSX      EAX, AL
#     SUB        EBP, 0x4
#     MOV        DWORD PTR [EBP], EAX
#     */
#     strings:
#         $hex_1 = { 8a 46 ff [0-40] 4e [0-40] 0f be c0 [0-40] 83 ed 04 [0-40] 89 45 00 }
#
#
#     condition:
#         all of them
# }
