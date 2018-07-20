"""This module provides translations of WProtect instruction into
Assembly Language.
"""

from keystone import Ks, KS_ARCH_X86, KS_MODE_32
import semantic.jumps


def _init():
    assembly = ""
    for i in range(0xc8):
        assembly += "reg_%s: .byte 0;" % i
    return assembly


def _pop_8(reg):
    assert len(reg) == 1
    return "INC esp; MOV %sl, ss:[esp];" % reg


def _push_8(reg):
    assert len(reg) == 1
    return "DEC esp; MOV %sl, ss:[esp];" % reg


SHLD = "POP eax; POP ebx; %s SHLD eax, edx, cl; PUSH eax; PUSHFD;" \
        % _pop_8("c")
SHRD = "POP eax; POP ebx; %s SHRD eax, edx, cl; PUSH eax; PUSHFD;" \
        % _pop_8("c")

B_WRITE_STACK = "MOV eax, 0%sh; %s; MOV BYTE PTR [esp + eax], bl;" \
        % ("%x", _pop_8("b"))
W_WRITE_STACK = "MOV eax, 0%xh; POP bx; MOV WORD PTR [esp + eax], bx;"
D_WRITE_STACK = "MOV eax, 0%xh; POP bl; MOV DWORD PTR [esp + eax], eax;"

B_READ_STACK = "MOV eax, 0%sh; MOV al, BYTE PTR [esp + eax]; %s" \
        % ("%x", _push_8("a"))
W_READ_STACK = "MOV eax, 0%xh; MOV ax, WORD PTR [esp + eax]; PUSH ax;"
D_READ_STACK = "MOV eax, 0x%h; MOV eax, DWORD PTR [esp + eax]; PUSH eax;"

B_WRITE_MEM = "POP eax; %s MOV BYTE PTR [eax], bl;" % _pop_8("b")
W_WRITE_MEM = "POP eax; POP bx; MOV BYTE PTR [eax], bx;"
D_WRITE_MEM = "POP eax; POP ebx; MOV BYTE PTR [eax], ebx;"

B_READ_MEM = "POP eax; MOV al, BYTE PTR [eax]; %s;" % _push_8("a")
W_READ_MEM = "POP eax; MOV ax, WORD PTR [eax]; PUSH ax;"
D_READ_MEM = "POP eax; MOV eax, DWORD PTR [eax]; PUSH eax;"

B_SHR = "%s %s SHR al, cl; %s; PUSHFD;" \
        % (_pop_8("b"), _pop_8("a"), _push_8("a"))
W_SHR = "%s POP ax; SHR ax, cl; PUSH ax; PUSHFD;" % _pop_8("b")
D_SHR = "%s POP eax; SHR eax, cl; PUSH eax; PUSHFD;" % _pop_8("b")

B_SHL = "%s %s SHL al, cl; %s; PUSHFD;" \
        % (_pop_8("b"), _pop_8("a"), _push_8("a"))
W_SHL = "%s POP ax; SHL ax, cl; PUSH ax; PUSHFD;" % _pop_8("b")
D_SHL = "%s POP eax; SHL eax, cl; PUSH eax; PUSHFD;" % _pop_8("b")

B_POP_REG = "%s ; MOV [reg_%s], al;" % (_pop_8("a"), "%s")
W_POP_REG = "POP ax; MOV [reg_%s], ax;"
D_POP_REG = "POP eax; MOV [reg_%s], eax;"

B_PUSH_REG = "MOV al, [reg_%s]; %s" % ("%s", _push_8("a"))
W_PUSH_REG = "MOV ax, [reg_%s]; PUSH ax;"
D_PUSH_REG = "MOV eax, [reg_%s]; PUSH eax;"

B_NAND = "%s NOT al; %s NOT bl; AND al, bl; %s PUSHFD;" \
        % (_pop_8("a"), _pop_8("b"), _push_8("a"))
W_NAND = "POP ax; NOT ax; POP bx; NOT bx; AND ax, bx; PUSH ax; PUSHFD;"
D_NAND = "POP eax; NOT eax; POP ebx; NOT ebx; AND aex, ebx; PUSH eax; PUSHFD;"
B_PUSH_IMM = "MOV al, 0%sh; %s;" % ("%x", _push_8("a"))
W_PUSH_IMM = "MOV ax, 0%xh; PUSH ax;"
D_PUSH_IMM = "MOV eax, 0%xh; PUSH eax;"

B_PUSH_IMM_ZX = "MOV al, 0%xh; MOVZX eax, al; PUSH eax;"
W_PUSH_IMM_ZX = "MOV ax, 0%xh; MOVZX eax, ax; PUSH eax;"
B_PUSH_IMM_SX = "MOV al, 0%xh; MOVSX eax, al; PUSH eax;"
W_PUSH_IMM_SX = "MOV ax, 0%xh; MOVSX eax, ax; PUSH eax;"

B_ROR = "%s %s ROR al, cl; %s; PUSHFD;" \
        % (_pop_8("b"), _pop_8("a"), _push_8("a"))
W_ROR = "%s POP ax; ROR ax, cl; PUSH ax; PUSHFD;" % _pop_8("b")
D_ROR = "%s POP eax; ROR eax, cl; PUSH eax; PUSHFD;" % _pop_8("b")

B_ROL = "%s %s ROL al, cl; %s; PUSHFD;" \
        % (_pop_8("b"), _pop_8("a"), _push_8("a"))
W_ROL = "%s POP ax; ROL ax, cl; PUSH ax; PUSHFD;" % _pop_8("b")
D_ROL = "%s POP eax; ROL eax, cl; PUSH eax; PUSHFD;" % _pop_8("b")

B_ADD = "%s %s ADD al, cl; %s; PUSHFD;" \
        % (_pop_8("b"), _pop_8("a"), _push_8("a"))
W_ADD = "POP cx; POP ax; ADD ax, cx; PUSH ax; PUSHFD;"
D_ADD = "POP ecx; POP eax; ADD eax, ecx; PUSH eax; PUSHFD;"

SET_PC = semantic.jumps.guess_conditional_jump
SET_KEY = SET_PC

CPUID = "CPUID; PUSH eax; PUSH ebx; PUSH ecx; PUSH edx;"
RDTSC = "RDTSC; PUSH edx; PUSH eax;"
NOP = ""

DISPATCH = "FWAIT; FNSTSW ax; PUSH ax;"
RUN_STACK = "%s; MOVZX eax, al; MOV ebx, esi; ADD esi, eax; CALL ebx;"\
        % _pop_8("a")

RET = "ret;"
POP_STACK_TOP_BASE = "POP ESP;"
PUSH_STACK_TOP_BASE = "PUSH ESP;"

TRANSLATION_TABLE = {
    "shld": SHLD,
    "shrd": SHRD,

    "b_write_stack": B_WRITE_STACK,
    "w_write_stack": W_WRITE_STACK,
    "d_write_stack": D_WRITE_STACK,

    "b_read_stack": B_READ_STACK,
    "w_read_stack": W_READ_STACK,
    "d_read_stack": D_READ_STACK,

    "b_write_mem": B_WRITE_MEM,
    "w_write_mem": W_WRITE_MEM,
    "d_write_mem": D_WRITE_MEM,

    "b_read_mem": B_READ_MEM,
    "w_read_mem": W_READ_MEM,
    "d_read_mem": D_READ_MEM,

    "b_shr": B_SHR,
    "w_shr": W_SHR,
    "d_shr": D_SHR,

    "b_shl": B_SHL,
    "w_shl": W_SHL,
    "d_shl": D_SHL,

    "b_pop_reg": B_POP_REG,
    "w_pop_reg": W_POP_REG,
    "d_pop_reg": D_POP_REG,

    "b_push_reg": B_PUSH_REG,
    "w_push_reg": W_PUSH_REG,
    "d_push_reg": D_PUSH_REG,

    "b_nand": B_NAND,
    "w_nand": W_NAND,
    "d_nand": D_NAND,
    "b_push_imm": B_PUSH_IMM,
    "w_push_imm": W_PUSH_IMM,
    "d_push_imm": D_PUSH_IMM,

    "b_push_imm_zx": B_PUSH_IMM_ZX,
    "w_push_imm_zx": W_PUSH_IMM_ZX,
    "b_push_imm_sx": B_PUSH_IMM_SX,
    "w_push_imm_sx": W_PUSH_IMM_SX,

    "b_ror": B_ROR,
    "w_ror": W_ROR,
    "d_ror": D_ROR,

    "b_rol": B_ROL,
    "w_rol": W_ROL,
    "d_rol": D_ROL,

    "b_add": B_ADD,
    "w_add": W_ADD,
    "d_add": D_ADD,

    "set_pc": SET_PC,
    "set_key": SET_KEY,

    "cpuid": CPUID,
    "rdtsc": RDTSC,
    "nop": NOP,

    "dispatch": DISPATCH,
    "run_stack": RUN_STACK,

    "ret": RET,
    "pop_stack_top_base": POP_STACK_TOP_BASE,
    "push_stack_top_base": PUSH_STACK_TOP_BASE,

}


def translate_blocks(blocks):
    """Translate code blocks into the machine code.

    Args:
        blocks (dict): dictionary of blocks indexed by offsets

    Returns:
        str: assembly code
    """
    def fill_instruction(instruction, block):
        template = TRANSLATION_TABLE[instruction["instruction"].name]
        if "_imm" in instruction["instruction"].name:
            return template % instruction["params"][0]
        elif "_reg" in instruction["instruction"].name:
            return template % instruction["params"][0]
        elif instruction["instruction"].name in ["set_key", "set_pc"]:
            template = template(block)
            return template % tuple(instruction["successors"])
        else:
            return template

    def assemble(code, entry_point):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        asm = "%s JMP offset_%s; %s" % (_init(), entry_point, code)
        # print asm.replace("; ", "\n").replace(";", "\n")
        return "".join(map(chr, ks.asm(asm)[0]))

    asm = ""
    entry_point = 0x0
    for offset, block in blocks.iteritems():
        entry_point = max(entry_point, offset)
        assembly = "offset_%s:; %s" % (offset, "".join(
            [fill_instruction(x, block) for x in block]))
        asm += assembly
    return assemble(asm, entry_point)
