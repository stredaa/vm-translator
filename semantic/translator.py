"""Contains WProtect instruction translations into Assembly Language.
Intended for Keystone assembler.
"""


def init(stack_size):
    return b"ADD esp, %i;" % stack_size


SHLD = b"POP eax; POP ebx; POP cl; SHLD eax, edx, cl; PUSH eax; PUSHFD;"
SHRD = b"POP eax; POP ebx; POP cl; SHRD eax, edx, cl; PUSH eax; PUSHFD;"

B_READ_STACK = b"MOV eax, 0%xh; MOV al, BYTE PTR [esp + eax]; MOVZX eax, al;PUSH eax;"
W_READ_STACK = b"MOV eax, 0%xh; MOV ax, WORD PTR [esp + eax]; PUSH ax;"
D_READ_STACK = b"MOV eax, 0x%h; MOV eax, DWORD PTR [esp + eax]; PUSH eax;"

B_WRITE_MEM = b"POP eax; POP bl; MOV BYTE PTR [eax], DL"
