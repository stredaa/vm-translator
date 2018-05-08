from logging import getLogger, StreamHandler, Formatter, DEBUG, INFO
from sys import stdout
import yara

from miasm2.analysis.binary import Container
from miasm2.core.asmblock import AsmLabel
from miasm2.core.interval import interval
from miasm2.analysis.machine import Machine
from miasm2.expression.expression import ExprId
from miasm2.core.utils import upck32

from vm.mnemonic import Mnemonic


class ASMBlock():
    def __init__(self, lines):
        self.code = lines

    def asm(self):
        return [line.b for line in self.code]


class PEAnalysis(object):
    def _set_logging(self, verbose):
        self._logger = getLogger(hex(hash(self)))
        if verbose:
            self._logger.setLevel(DEBUG)
        else:
            self._logger.setLevel(INFO)
        log_handler = StreamHandler(stdout)
        log_handler.setFormatter(Formatter('[%(levelname)s]\t%(message)s'))
        self._logger.addHandler(log_handler)

    def __init__(self, filename, verbose=False):
        self._container = Container.from_stream(open(filename))
        self.bin_stream = self._container.bin_stream
        self.entry_point = self._container.entry_point
        self.machine = Machine(self._container.arch)

        self.fn = {}
        self.interval = interval()
        self.deep = 0
        self.offset = 0

        self._set_logging(verbose)
        self._logger.info("PE loaded")

    def _update_interval(self, block):
        for l in block.lines:
            self.interval += interval([(l.offset, l.offset + l.l)])

    def process_fn(self, offset):
        if offset in self.fn:
            return

        mdis = self.machine.dis_engine(self.bin_stream)
        self.fn[offset] = mdis.dis_multiblock(offset)
        self._logger.debug("sub_" + hex(offset)[2:] + " added")

        map(self._update_interval, self.fn[offset])

        for block in self.fn[offset]:
            instr = block.get_subcall_instr()
            if not instr:
                continue
            for dest in instr.getdstflow(mdis.symbol_pool):
                if not (isinstance(dest, ExprId)
                        and isinstance(dest.name, AsmLabel)):
                    continue
                self.process_fn(dest.name.offset)

    def process_rest(self):
        for _, right in self.interval.intervals:
            if right in self.fn:
                continue
            self.process_fn(right)

    def analyze(self, analyze_unreachable=False):
        self.process_fn(self.entry_point)
        self._logger.info("reachable code analysis done")
        self.deep = 1
        if analyze_unreachable:
            self.deep = 2
            self.process_rest()
            self._logger.info("unreachable code analysis done")


class WProtectEmulator(PEAnalysis):
    def detect(self, block):
        data = "".join(map(lambda x: x.b, block.lines))
        switch = yara.compile("WProtect.yara")
        match = switch.match(data=data)
        if "WProtect" not in map(lambda x: x.rule, match):
            return -1
        # verify jump table
        # yara-rule/condition/hexstring
        offset = upck32(match[0].strings[0][2][-5:-1])
        first_mnemonic = upck32(self.bin_stream.getbytes(offset + 4, 4))
        mdis = self.machine.dis_engine(self.bin_stream)
        last_mnemonic_instruction = mdis.dis_block(first_mnemonic).lines[-1]

        # Every mnemonic block ends with a JMP/RET/CALL or conditional jump
        if not (last_mnemonic_instruction.name in ["JMP", "RET", "CALL"]
                or last_mnemonic_instruction.name.startswith("J")):
            return -1

        self._logger.info(
            "WProtect vm mnemonics found at offset " + hex(offset))
        self.offset = offset

        return offset

    def _filter(self):
        processed = [[self.detect(block)
                      for block in fn]
                     for fn in self.fn.values()]

        return filter(lambda x: x >= 0,
                      [item for sublist in processed for item in sublist])

    def find(self, override_unreachable=False):
        if override_unreachable and self.deep < 2:
            self._logger.info(
                "optimization overriden, analyzing unreachable code")
            self.analyze(analyze_unreachable=True)
        elif self.deep == 0:
            self.analyze(analyze_unreachable=False)

        processed = self._filter()
        if not processed:
            if override_unreachable:
                self._logger.error("WProtect VM not found")
                return False
            else:
                self._logger.error(
                    "WProtect VM not found, retry with unreachable \
                    code analysis")
                self.find(override_unreachable=True)
        self.vm_offset = processed
        return True

    def recover_mnemonics(self, offset, mnemonic_cls, amount=56):
        def get_block(offset):
            mdis = self.machine.dis_engine(self.bin_stream)
            block = mdis.dis_block(offset)

            # extend a block ending with CALL by a following block
            if block.lines[-1].name in ["CALL", "JA"]:
                lines = mdis.dis_block(block.get_next().offset).lines
                for line in lines:
                    block.addline(line)
            return block.lines

        if not issubclass(mnemonic_cls, Mnemonic):
            raise TypeError("Given mnemonic class does not inherit Mnemonic!")

        addresses = [upck32(self.bin_stream.getbytes(
            offset + 4 + 4 * i, 4)) for i in range(amount)]
        magic_dword = upck32(self.bin_stream.getbytes(offset, 4))
        self._logger.debug("magic DWORD: " + hex(magic_dword))
        mnemonics = map(lambda x: mnemonic_cls(get_block(x)), addresses)
        self._logger.info("Mnemonics loaded")
        return magic_dword, mnemonics
