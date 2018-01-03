from miasm2.analysis.binary import Container
from miasm2.core.asmblock import AsmLabel
from miasm2.core.interval import interval
from miasm2.analysis.machine import Machine
from miasm2.expression.expression import ExprId

from miasm2.core.utils import upck32
from logging import getLogger, StreamHandler, Formatter, DEBUG, INFO
from sys import stdout

from abc import ABCMeta


class abstractstatic(staticmethod):
    __slots__ = ()

    def __init__(self, function):
        super(abstractstatic, self).__init__(function)
        function.__isabstractmethod__ = True
    __isabstractmethod__ = True


class Mnemonic(object):
    __metaclass__ = ABCMeta

    @abstractstatic
    def recognize(code):
        pass

    def _set_logging(self, verbose):
        self._logger = getLogger(hex(hash(self)))
        if verbose:
            self._logger.setLevel(DEBUG)
        else:
            self._logger.setLevel(INFO)
        log_handler = StreamHandler(stdout)
        log_handler.setFormatter(Formatter('[%(levelname)s]\t%(message)s'))
        self._logger.addHandler(log_handler)

    def __init__(self, code, verbose=False):
        self.code = code
        self.name = self.recognize(code)
        self._set_logging(verbose)

    def __str__(self):
        return self.name


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
        for a, b in self.interval.intervals:
            if b in self.fn:
                continue
            self.process_fn(b)

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
        # 2 instructions are checked
        if not (len(block.lines) >= 2):
            return -1

        # PUSH of a given format and RET are required for a switch idiom
        push_addr = "PUSH       DWORD PTR [EAX * 0x4 + 0x"
        retn = "RET"
        if not ((block.lines[-1].name == retn)
                and (str(block.lines[-2])[0:len(push_addr)] == push_addr)):
            return -1

        # verify jump table
        offset = int(str(block.lines[-2])[len(push_addr):-1], 16)
        first_mnemonic = upck32(self.bin_stream.getbytes(offset + 4, 4))
        mdis = self.machine.dis_engine(self.bin_stream)
        last_mnemonic_instruction = mdis.dis_block(first_mnemonic).lines[-1]

        # Every mnemonic block ends with a JMP/RET/CALL or conditional jump
        if not (last_mnemonic_instruction.name in ["JMP", "RET", "CALL"]
                or last_mnemonic_instruction.name.startswith("J")):
            return -1

        self._logger.info(
            "WProtect vm mnemonics found at offset " + hex(offset))

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
            else:
                self._logger.error(
                    "WProtect VM not found, retry with unreachable \
                    code analysis")
                self.find(override_unreachable=True)
        self.vm_offset = processed

    def recoverMnemonics(self, offset, mnemonic_cls, amount=56):
        def getBlock(offset):
            mdis = self.machine.dis_engine(self.bin_stream)
            block = mdis.dis_bloc(offset)

            # extend a block ending with CALL by a following block
            if block.lines[-1].name in ["CALL", "JA"]:
                lines = mdis.dis_bloc(block.get_next().offset).lines
                for line in lines:
                    block.addline(line)
            return block.lines

        if not issubclass(mnemonic_cls, Mnemonic):
            raise TypeError("Given mnemonic class does not inherit Mnemonic!")

        addresses = [upck32(self.bin_stream.getbytes(
            offset + 4 + 4 * i, 4)) for i in xrange(amount)]
        magic_dword = upck32(self.bin_stream.getbytes(offset, 4))
        self._logger.debug("magic DWORD: " + hex(magic_dword))
        mnemonics = map(lambda x: mnemonic_cls(getBlock(x)), addresses)
        self._logger.info("Mnemonics loaded")
        return magic_dword, mnemonics
