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
        bin_stream = bin_stream_str(asm)
        mdis = machine.dis_engine(bin_stream)
        asm_block = mdis.dis_block(0)
        ira = machine.ira(mdis.symbol_pool)
        ira.add_block(asm_block)
        symbols_init = ira.arch.regs.all_regs_ids_byname
        return SymbolicExecutionEngine(ira, symbols_init)

    i = 0
    asm = ""
    while not filter_fn(code[i]):
        i += 1
    while filter_fn(code[i]):
        asm += code[i].b
        i += 1
    symbolic = load_asm(asm)
    symbolic.emul_ir_block(0)
    translator = TranslatorPython()
    return lambda EBX: eval(
        translator.from_expr(symbolic.symbols[ExprId("EBX", 3, 2)]))


def strip_vm_obfuscation(code):
#    def is_jump(line):
#        return line.name[0] == "J"

#    has_imm = any(["ESI" in str(i) for i in code])

#    relevant_code = filter(lambda x: len(x.args) == 0
#                           or not (is_ebx(x)
#                                   or (is_eax(x) and has_imm)
#                                   or is_jump(x)), code)
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
