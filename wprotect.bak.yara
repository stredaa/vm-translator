rule mnemonic_0
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        EDX, DWORD PTR [EBP + 0x4]
    MOV        CL, BYTE PTR [EBP + 0x8]
    INC        EBP
    SHLD       EAX, EDX, CL
    MOV        DWORD PTR [EBP + 0x4], EAX
    PUSHFD
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8bU\x04.{0,50}\x8aM\x08.{0,50}E.{0,50}\x0f\xa5\xd0.{0,50}\x89E\x04.{0,50}\x9c.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_1
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        AX, WORD PTR [EAX + EBP]
    SUB        EBP, 0x2
    MOV        WORD PTR [EBP], AX
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}f\x8bD\x05\x00.{0,50}\x83\xed\x02.{0,50}f\x89E\x00/


    condition:
        all of them
}
rule mnemonic_2
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        DL, BYTE PTR [EBP + 0x4]
    ADD        EBP, 0x5
    MOV        BYTE PTR [EAX], DL
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8aU\x04.{0,50}\x83\xc5\x05.{0,50}\x88\x10/


    condition:
        all of them
}
rule mnemonic_3
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        EAX, DWORD PTR [EAX]
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8b\x00.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_4
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AL, BYTE PTR [EBP]
    SHL        AL, CL
    MOV        BYTE PTR [EBP], AL
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8aE\x00.{0,50}\xd2\xe0.{0,50}\x88E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_5
{
    /*
    MOV        EBP, DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8bm\x00/


    condition:
        all of them
}
rule mnemonic_6
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        EAX, DWORD PTR [EAX + EDI]
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}\x8b\x04\x07.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_7
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AL, BYTE PTR [EBP]
    SHR        AL, CL
    MOV        BYTE PTR [EBP], AL
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8aE\x00.{0,50}\xd2\xe8.{0,50}\x88E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_8
{
    /*
    MOV        AX, WORD PTR [EBP]
    NOT        AX
    ADD        EBP, 0x2
    MOV        DX, WORD PTR [EBP]
    NOT        DX
    AND        AX, DX
    MOV        WORD PTR [EBP], AX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /f\x8bE\x00.{0,50}f\xf7\xd0.{0,50}\x83\xc5\x02.{0,50}f\x8bU\x00.{0,50}f\xf7\xd2.{0,50}f#\xc2.{0,50}f\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_9
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AX, WORD PTR [EBP]
    SHR        AX, CL
    MOV        WORD PTR [EBP], AX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}f\x8bE\x00.{0,50}f\xd3\xe8.{0,50}f\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_10
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    DEC        EBP
    MOV        BYTE PTR [EBP], AL
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}M.{0,50}\x88E\x00/


    condition:
        all of them
}
rule mnemonic_11
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        EAX, DWORD PTR [EBP]
    SHL        EAX, CL
    MOV        DWORD PTR [EBP], EAX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8bE\x00.{0,50}\xd3\xe0.{0,50}\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_12
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        DL, BYTE PTR [EBP]
    MOV        BYTE PTR [EAX + EBP], DL
    INC        EBP
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}\x8aU\x00.{0,50}\x88T\x05\x00.{0,50}E/


    condition:
        all of them
}
rule mnemonic_13
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        EAX, DWORD PTR [EBP]
    ROR        EAX, CL
    MOV        DWORD PTR [EBP], EAX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8bE\x00.{0,50}\xd3\xc8.{0,50}\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_14
{
    /*
    MOV        EAX, EBP
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8b\xc5.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_15
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AX, WORD PTR [EBP]
    ROL        AX, CL
    MOV        WORD PTR [EBP], AX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}f\x8bE\x00.{0,50}f\xd3\xc0.{0,50}f\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_16
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        EDX, DWORD PTR [EBP + 0x4]
    ADD        EBP, 0x8
    MOV        DWORD PTR [EAX], EDX
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8bU\x04.{0,50}\x83\xc5\x08.{0,50}\x89\x10/


    condition:
        all of them
}
rule mnemonic_17
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        AL, BYTE PTR [EAX + EDI]
    DEC        EBP
    MOV        BYTE PTR [EBP], AL
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}\x8a\x04\x07.{0,50}M.{0,50}\x88E\x00/


    condition:
        all of them
}
rule mnemonic_18
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    ADD        EBP, 0x3
    MOV        AL, BYTE PTR [EAX]
    MOV        BYTE PTR [EBP], AL
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x83\xc5\x03.{0,50}\x8a\x00.{0,50}\x88E\x00/


    condition:
        all of them
}
rule mnemonic_19
{
    /*
    CMP        EBP, EAX
    LEA        ECX, DWORD PTR [EDI + 0x64]
    SUB        ECX, EDI
    MOV        ESP, EAX
    PUSH       ESI
    MOV        ESI, EDI
    MOV        EDI, EAX
    MOV        EDX, ECX
    CLD
    REPE MOVSB
    SUB        EDI, EDX
    POP        ESI
    */
    strings:
        $re_1 = /;\xe8.{0,50}\x8dOd.{0,50}+\xcf.{0,50}\x8b\xe0.{0,50}V.{0,50}\x8b\xf7.{0,50}\x8b\xf8.{0,50}\x8b\xd1.{0,50}\xfc.{0,50}\xf3\xa4.{0,50}+\xfa.{0,50}^/


    condition:
        all of them
}
rule mnemonic_20
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        EAX, DWORD PTR [EBP]
    SHR        EAX, CL
    MOV        DWORD PTR [EBP], EAX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8bE\x00.{0,50}\xd3\xe8.{0,50}\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_21
{
    /*
    MOV        AL, BYTE PTR [EBP]
    NOT        AL
    INC        EBP
    MOV        DL, BYTE PTR [EBP]
    NOT        DL
    AND        AL, DL
    MOV        BYTE PTR [EBP], AL
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aE\x00.{0,50}\xf6\xd0.{0,50}E.{0,50}\x8aU\x00.{0,50}\xf6\xd2.{0,50}"\xc2.{0,50}\x88E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_22
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    NOT        EAX
    ADD        EBP, 0x4
    MOV        EDX, DWORD PTR [EBP]
    NOT        EDX
    AND        EAX, EDX
    MOV        DWORD PTR [EBP], EAX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\xf7\xd0.{0,50}\x83\xc5\x04.{0,50}\x8bU\x00.{0,50}\xf7\xd2.{0,50}#\xc2.{0,50}\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_23
{
    /*
    MOV        AL, BYTE PTR [EBP]
    MOVZX      EAX, AL
    INC        EBP
    MOV        EDX, EBP
    ADD        EBP, EAX
    CALL       EDX
    */
    strings:
        $re_1 = /\x8aE\x00.{0,50}\x0f\xb6\xc0.{0,50}E.{0,50}\x8b\xd5.{0,50}\x03\xe8.{0,50}\xff\xd2/


    condition:
        all of them
}
rule mnemonic_24
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_25
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        DL, BYTE PTR [EBP]
    MOV        BYTE PTR [EAX + EDI], DL
    INC        EBP
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}\x8aU\x00.{0,50}\x88\x14\x07.{0,50}E/


    condition:
        all of them
}
rule mnemonic_26
{
    /*
    CPUID
    SUB        EBP, 0x10
    MOV        DWORD PTR [EBP + 0xC], EAX
    MOV        DWORD PTR [EBP + 0x8], EBX
    MOV        DWORD PTR [EBP + 0x4], ECX
    MOV        DWORD PTR [EBP], EDX
    */
    strings:
        $re_1 = /\x0f\xa2.{0,50}\x83\xed\x10.{0,50}\x89E\x0c.{0,50}\x89]\x08.{0,50}\x89M\x04.{0,50}\x89U\x00/


    condition:
        all of them
}
rule mnemonic_27
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AX, WORD PTR [EBP]
    ROR        AX, CL
    MOV        WORD PTR [EBP], AX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}f\x8bE\x00.{0,50}f\xd3\xc8.{0,50}f\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_28
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AX, WORD PTR [EBP]
    SHL        AX, CL
    MOV        WORD PTR [EBP], AX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}f\x8bE\x00.{0,50}f\xd3\xe0.{0,50}f\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_29
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        DX, WORD PTR [EBP]
    MOV        WORD PTR [EAX + EBP], DX
    ADD        EBP, 0x2
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}f\x8bU\x00.{0,50}f\x89T\x05\x00.{0,50}\x83\xc5\x02/


    condition:
        all of them
}
rule mnemonic_30
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        AL, BYTE PTR [EAX + EBP]
    SUB        EBP, 0x1
    MOV        BYTE PTR [EBP], AL
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}\x8a\x04(.{0,50}\x83\xed\x01.{0,50}\x88E\x00/


    condition:
        all of them
}
rule mnemonic_31
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        EAX, DWORD PTR [EBP]
    ROL        EAX, CL
    MOV        DWORD PTR [EBP], EAX
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8bE\x00.{0,50}\xd3\xc0.{0,50}\x89E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_32
{
    /*
    RDTSC
    SUB        EBP, 0x8
    MOV        DWORD PTR [EBP], EDX
    MOV        DWORD PTR [EBP + 0x4], EAX
    */
    strings:
        $re_1 = /\x0f1.{0,50}\x83\xed\x08.{0,50}\x89U\x00.{0,50}\x89E\x04/


    condition:
        all of them
}
rule mnemonic_33
{

    strings:
        $re_1 = //


    condition:
        all of them
}
rule mnemonic_34
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    ADD        EBP, 0x2
    MOV        AX, WORD PTR [EAX]
    MOV        WORD PTR [EBP], AX
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x83\xc5\x02.{0,50}f\x8b\x00.{0,50}f\x89E\x00/


    condition:
        all of them
}
rule mnemonic_35
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        DX, WORD PTR [EBP]
    MOV        WORD PTR [EAX + EDI], DX
    ADD        EBP, 0x2
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}f\x8bU\x00.{0,50}f\x89\x14\x07.{0,50}\x83\xc5\x02/


    condition:
        all of them
}
rule mnemonic_36
{
    /*
    MOV        AX, WORD PTR [EBP]
    ADD        WORD PTR [EBP + 0x2], AX
    PUSHFD
    SUB        EBP, 0x2
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /f\x8bE\x00.{0,50}f\x01E\x02.{0,50}\x9c.{0,50}\x83\xed\x02.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_37
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        EDX, DWORD PTR [EBP]
    MOV        DWORD PTR [EAX + EBP], EDX
    ADD        EBP, 0x4
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}\x8bU\x00.{0,50}\x89T\x05\x00.{0,50}\x83\xc5\x04/


    condition:
        all of them
}
rule mnemonic_38
{
    /*
    SUB        EBP, 0x2
    FWAIT
    FNSTSW     AX
    MOV        WORD PTR [EBP], AX
    */
    strings:
        $re_1 = /\x83\xed\x02.{0,50}\x9b.{0,50}\xdf\xe0.{0,50}f\x89E\x00/


    condition:
        all of them
}
rule mnemonic_39
{
    /*
    MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
    SUB        ESI, 0x2
    MOVZX      EAX, AX
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /f\x8bF\xfe.{0,50}\x83\xee\x02.{0,50}\x0f\xb7\xc0.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_40
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        AX, WORD PTR [EAX + EDI]
    SUB        EBP, 0x2
    MOV        WORD PTR [EBP], AX
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}f\x8b\x04\x07.{0,50}\x83\xed\x02.{0,50}f\x89E\x00/


    condition:
        all of them
}
rule mnemonic_41
{
    /*
    MOV        AL, BYTE PTR [EBP]
    ADD        BYTE PTR [EBP + 0x1], AL
    PUSHFD
    SUB        EBP, 0x3
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aE\x00.{0,50}\x00E\x01.{0,50}\x9c.{0,50}\x83\xed\x03.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_42
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AL, BYTE PTR [EBP]
    ROL        AL, CL
    MOV        BYTE PTR [EBP], AL
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8aE\x00.{0,50}\xd2\xc0.{0,50}\x88E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_43
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        EDX, DWORD PTR [EBP + 0x4]
    MOV        CL, BYTE PTR [EBP + 0x8]
    INC        EBP
    SHRD       EAX, EDX, CL
    MOV        DWORD PTR [EBP + 0x4], EAX
    PUSHFD
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8bU\x04.{0,50}\x8aM\x08.{0,50}E.{0,50}\x0f\xad\xd0.{0,50}\x89E\x04.{0,50}\x9c.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_44
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_45
{
    /*
    MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
    SUB        ESI, 0x2
    SUB        EBP, 0x2
    MOV        WORD PTR [EBP], AX
    */
    strings:
        $re_1 = /f\x8bF\xfe.{0,50}\x83\xee\x02.{0,50}\x83\xed\x02.{0,50}f\x89E\x00/


    condition:
        all of them
}
rule mnemonic_46
{
    /*
    MOV        EBX, DWORD PTR [EBP]
    ADD        EBP, 0x4
    MOV        EAX, DWORD PTR [EBP]
    MOV        ESI, EAX
    ADD        EBP, 0x4
    */
    strings:
        $re_1 = /\x8b]\x00.{0,50}\x83\xc5\x04.{0,50}\x8bE\x00.{0,50}\x8b\xf0.{0,50}\x83\xc5\x04/


    condition:
        all of them
}
rule mnemonic_47
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    ADD        DWORD PTR [EBP + 0x4], EAX
    PUSHFD
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x01E\x04.{0,50}\x9c.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_48
{
    /*
    MOV        ESP, EBP
    POP        EDI
    POP        ESI
    POP        EBP
    POP        EDX
    POP        ECX
    POPFD
    RET
    */
    strings:
        $re_1 = /\x8b\xe5.{0,50}_.{0,50}^.{0,50}].{0,50}Z.{0,50}Y.{0,50}\x9d.{0,50}\xc3/


    condition:
        all of them
}
rule mnemonic_49
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        DX, WORD PTR [EBP + 0x4]
    ADD        EBP, 0x6
    MOV        WORD PTR [EAX], DX
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}f\x8bU\x04.{0,50}\x83\xc5\x06.{0,50}f\x89\x10/


    condition:
        all of them
}
rule mnemonic_50
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVZX      EAX, AL
    MOV        EDX, DWORD PTR [EBP]
    MOV        DWORD PTR [EAX + EDI], EDX
    ADD        EBP, 0x4
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xb6\xc0.{0,50}\x8bU\x00.{0,50}\x89\x14\x07.{0,50}\x83\xc5\x04/


    condition:
        all of them
}
rule mnemonic_51
{
    /*
    MOV        EAX, DWORD PTR [EBP]
    MOV        ESI, EAX
    ADD        EBP, 0x4
    */
    strings:
        $re_1 = /\x8bE\x00.{0,50}\x8b\xf0.{0,50}\x83\xc5\x04/


    condition:
        all of them
}
rule mnemonic_52
{
    /*
    MOV        EAX, DWORD PTR [ESI + 0xFFFFFFFC]
    SUB        ESI, 0x4
    MOV        EAX, DWORD PTR [EAX + EBP]
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8bF\xfc.{0,50}\x83\xee\x04.{0,50}\x8bD\x05\x00.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_53
{
    /*
    MOV        AX, WORD PTR [ESI + 0xFFFFFFFE]
    SUB        ESI, 0x2
    MOVSX      EAX, AX
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /f\x8bF\xfe.{0,50}\x83\xee\x02.{0,50}\x0f\xbf\xc0.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
rule mnemonic_54
{
    /*
    MOV        CL, BYTE PTR [EBP]
    INC        EBP
    MOV        AL, BYTE PTR [EBP]
    ROR        AL, CL
    MOV        BYTE PTR [EBP], AL
    PUSHFD
    SUB        EBP, 0x4
    POP        DWORD PTR [EBP]
    */
    strings:
        $re_1 = /\x8aM\x00.{0,50}E.{0,50}\x8aE\x00.{0,50}\xd2\xc8.{0,50}\x88E\x00.{0,50}\x9c.{0,50}\x83\xed\x04.{0,50}\x8fE\x00/


    condition:
        all of them
}
rule mnemonic_55
{
    /*
    MOV        AL, BYTE PTR [ESI + 0xFFFFFFFF]
    DEC        ESI
    MOVSX      EAX, AL
    SUB        EBP, 0x4
    MOV        DWORD PTR [EBP], EAX
    */
    strings:
        $re_1 = /\x8aF\xff.{0,50}N.{0,50}\x0f\xbe\xc0.{0,50}\x83\xed\x04.{0,50}\x89E\x00/


    condition:
        all of them
}
