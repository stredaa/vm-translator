from miasm2.analysis.machine import Machine
from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.expression.expression import ExprId
from miasm2.core.bin_stream import bin_stream_str
from miasm2.ir.translators.python import TranslatorPython


def is_ebx(line):
    return (len(line.args) >= 1
            and str(line.args[0]) in ["EBX", "BX", "BL"]
            and not line.name == "MOV")


def is_eax(line):
    return (len(line.args) >= 1
            and str(line.args[0]) in ["EAX", "AX", "AL"]
            and (len(line.args) == 1
                 or ("0x" in str(line.args[1])
                     and "ESI" not in str(line.args[1]))
                 or str(line.args[1]) in ["EBX", "BX", "BL"]))


def extract_obfuscation(code, filter_fn, machine=Machine("x86_32")):
    def load_asm(asm):
        """Transform shellcode into a block and symbolically
        execute it.
        """
        bin_stream = bin_stream_str(asm)
        mdis = machine.dis_engine(bin_stream)
        asm_block = mdis.dis_block(0)
        ira = machine.ira(mdis.symbol_pool)
        ira.add_block(asm_block)
        symbols_init = ira.arch.regs.regs_init
        symbolic = SymbolicExecutionEngine(ira, symbols_init)
        symbolic.run_block_at(0)
        return symbolic

    i = 0
    asm = ""
    while i < len(code) and not filter_fn(code[i]):
        i += 1
    while i < len(code) and filter_fn(code[i]):
        asm += code[i].b
        i += 1
    symbolic = load_asm(asm)
    translator = TranslatorPython()

    def eax(EAX_init, EBX_init):
        return eval(translator.from_expr(symbolic.symbols[ExprId("EAX", 32)]))
    def ebx(EBX_init):
        return eval(translator.from_expr(symbolic.symbols[ExprId("EBX", 32)]))

    return {"eax": eax, "ebx": ebx}


def strip_vm_obfuscation(code):
    relevant_code = []
    is_esi = False
    ebx_init = True
    for line in code:
        if is_ebx(line) and ebx_init:
            continue
        ebx_init = False
        if is_esi:
            if not is_eax(line):
                is_esi = False
            else:
                continue
        if "ESI" in str(line):
            is_esi = True
        if line.name[0] == "J":
            continue
        relevant_code.append(line)

    return relevant_code


def get_bytes(code):
    return [line.b for line in code]
