import enum
import struct
from typing import TextIO

from ..arch import PowerPC64
from ..boards import Board, Arty
from . import Target


class DBG_WB(enum.IntEnum):
    ADDR = 0x00
    DATA = 0x01
    CTRL = 0x02


class DBG_CORE(enum.IntEnum):
    CTRL = 0x10
    CTRL_STOP = 1 << 0
    CTRL_RESET = 1 << 1
    CTRL_ICRESET = 1 << 2
    CTRL_STEP = 1 << 3
    CTRL_START = 1 << 4

    STAT = 0x11
    STAT_STOPPING = 1 << 0
    STAT_STOPPED = 1 << 1
    STAT_TERM = 1 << 2

    NIA = 0x12
    MSR = 0x13

    GSPR_INDEX = 0x14
    GSPR_DATA = 0x15


class DBG_LOG(enum.IntEnum):
    ADDR = 0x16
    DATA = 0x17
    TRIGGER = 0x18


DBG_REGNAMES = (
    [
        # GPRs
        "r" + str(gpr)
        for gpr in range(32)
    ]
    + [
        # SPRs
        "lr",
        "ctr",
        "srr0",
        "srr1",
        "hsrr0",
        "hsrr1",
        "sprg0",
        "sprg1",
        "sprg2",
        "sprg3",
        "hsprg0",
        "hsprg1",
        "xer",
    ]
    + ["spr" + str(spr) for spr in range(45, 64)]
    + [
        # FPRs
        "f" + str(fpr)
        for fpr in range(32)
    ]
)


def i642bytes(data: int, buffer: bytearray = bytearray(8), offset: int = 0) -> bytes:
    struct.pack_into("Q", buffer, offset, data)
    return buffer


def bytes2i64(buffer: bytes, offset: int = 0) -> int:
    assert (len(buffer) - offset) >= 8
    return struct.unpack_from("Q", buffer, offset)[0]


def is_aligned(value: int, boundary_in_bytes: int = 8):
    return (value & (boundary_in_bytes - 1)) == 0


def round_up(value: int, boundary_in_bytes: int = 8):
    return (value + (boundary_in_bytes - 1)) & ~(boundary_in_bytes - 1)


def round_down(value: int, boundary_in_bytes: int = 8):
    return value & ~(boundary_in_bytes - 1)


class Microwatt(Target):
    class Debug(object):
        def __init__(self):
            self._urc = None

        def __enter__(self):
            self.connect()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.disconnect()

        def __del__(self):
            self.disconnect()

        def connect(self, board):
            self._urc = board.chain()

            # from bscane2_init()
            self._urc.addpart(6)
            self._urc.add_register("IDCODE_REG", 32)
            self._urc.add_instruction("IDCODE", "001001", "IDCODE_REG")
            self._urc.add_register("USER2_REG", 74)
            self._urc.add_instruction("USER2", "000011", "USER2_REG")

            self.reg_IDCODE = self._urc.get_register(0, "IDCODE_REG", "IDCODE")
            self.reg_USER2 = self._urc.get_register(0, "USER2_REG", "USER2")

        def disconnect(self):
            if self._urc is not None:
                self._urc.disconnect()
                self._urc = None
                self.reg_IDCODE = None
                self.reg_USER2 = None

        def command(self, op, addr, data=0):
            self.reg_USER2.set_dr_in(op, 1, 0)
            self.reg_USER2.set_dr_in(int(data), 65, 2)
            self.reg_USER2.set_dr_in(int(addr), 73, 66)
            self.reg_USER2.shift_ir()
            self.reg_USER2.shift_dr()

            return self.reg_USER2.get_dr_out(1, 0), self.reg_USER2.get_dr_out(65, 2)

        def dmi_read(self, addr: int):
            rc, data = self.command(1, addr)
            while True:
                rc, data = self.command(0, 0)
                if rc == 0:
                    assert 0 <= data and data <= 0xFFFF_FFFF_FFFF_FFFF
                    return data
                elif rc != 3:
                    raise Exception("Unknown status code %d!" % rc)

        def dmi_write(self, addr: int, data: int):
            # Convert unsigned into signed 64bit (Python) int
            if addr > 0x7FFF_FFFF_FFFF_FFFF:
                addr = addr - (1 << 64)
            if data > 0x7FFF_FFFF_FFFF_FFFF:
                data = data - (1 << 64)
            rc, _ = self.command(2, addr, data)
            while True:
                rc, _ = self.command(0, 0)
                if rc == 0:
                    return
                elif rc != 3:
                    raise Exception("Unknown status code %d!" % rc)

        def register_read_nia(self) -> int:
            return self.dmi_read(DBG_CORE.NIA)

        def register_read_msr(self) -> int:
            return self.dmi_read(DBG_CORE.MSR)

        def register_read(self, regnum: int) -> int:
            assert 0 <= regnum and regnum < len(DBG_REGNAMES)
            self.dmi_write(DBG_CORE.GSPR_INDEX, regnum)
            return self.dmi_read(DBG_CORE.GSPR_DATA)

        def memory_read(self, addr: int, count: int = 1) -> list[int]:
            self.dmi_write(DBG_WB.CTRL, 0x7FF)
            self.dmi_write(DBG_WB.ADDR, addr)
            return [self.dmi_read(DBG_WB.DATA) for _ in range(count)]

        def memory_write(self, addr: int, data: int) -> None:
            self.dmi_write(DBG_WB.CTRL, 0x7FF)
            self.dmi_write(DBG_WB.ADDR, addr)
            self.dmi_write(DBG_WB.DATA, data)

        def status(self):
            return self.dmi_read(DBG_CORE.STAT)

        def status_string(self):
            stat = self.status()
            statstr = "running"
            statstr2 = ""
            if stat & DBG_CORE.STAT_STOPPED:
                statstr = "stopped"
                if not stat & DBG_CORE.STAT_STOPPING:
                    # if (!(stat & DBG_CORE_STAT_STOPPING))
                    statstr2 = " (restarting?)"
                elif stat & DBG_CORE.STAT_TERM:
                    # else if (stat & DBG_CORE_STAT_TERM)
                    statstr2 = " (terminated)"
            elif stat & DBG_CORE.STAT_STOPPING:
                # } else if (stat & DBG_CORE_STAT_STOPPING) {
                statstr = "stopping"
                if stat & DBG_CORE.STAT_TERM:
                    # if (stat & DBG_CORE_STAT_TERM)
                    statstr2 = " (terminated)"
            elif stat & DBG_CORE.STAT_TERM:
                # } else if (stat & DBG_CORE_STAT_TERM)
                statstr = "odd state (TERM but no STOP)"
            return statstr + statstr2

        def stop(self):
            self.dmi_write(DBG_CORE.CTRL, DBG_CORE.CTRL_STOP)

        def step(self):
            stat = self.status()
            assert (stat & DBG_CORE.STAT_STOPPED) != 0, "Core not stopped!"
            self.dmi_write(DBG_CORE.CTRL, DBG_CORE.CTRL_STEP)

        def start(self):
            self.dmi_write(DBG_CORE.CTRL, DBG_CORE.CTRL_START)

        def creset(self):
            self.dmi_write(DBG_CORE.CTRL, DBG_CORE.CTRL_RESET)

    def __init__(self, board : Board|None = None):
        """
        Initialize Microwatt on given board. If board is not specified,
        defaults to Arty.
        """
        super().__init__()
        self._cpustate = PowerPC64()
        if board is not None:
            self._board = board
        else:
            self._board = Arty()
        self._jtag = None

    def connect(self):
        if self._jtag is None:
            self._jtag = Microwatt.Debug()
            self._jtag.connect(self._board)

    def disconnect(self):
        if self._jtag is not None:
            self._jtag.disconnect()
            self._jtag = None

    def register_read(self, regnum: int) -> bytes:
        reg = self._cpustate.registers[regnum]
        # First, read the raw (as uint64) using JTAG
        if reg.name == "pc":
            raw = self._jtag.register_read_nia() & 0xFFFFFFFF
        elif reg.name == "msr":
            raw = self._jtag.register_read_msr()
        elif reg.name in DBG_REGNAMES:
            raw = self._jtag.register_read(DBG_REGNAMES.index(reg.name))
        else:
            # Register not supported by Microwatt (debug interface)
            raw = 0
        # Second, convert raw value back to bytes...
        value = i642bytes(raw)
        # ...and truncate to correct length
        value = value[0 : reg.size // 8]
        return value

    def register_write(self, regnum, data):
        raise Exception("Should be implemented!")

    def memory_read(self, addr: int, length: int) -> bytes:
        buflen = round_up(addr + length) - round_down(addr)
        buf = bytearray(buflen)
        offset = 0
        for word in self._jtag.memory_read(round_down(addr), len(buf) // 8):
            i642bytes(word, buf, offset)
            offset += 8
        buf_lo = addr - round_down(addr)
        buf_hi = buf_lo + length
        return buf[buf_lo:buf_hi]

    def memory_write(self, addr: int, data: bytes, length: int = None) -> None:
        if length is None:
            length = len(data)

        buflen = round_up(addr + length) - round_down(addr)
        buf = bytearray(buflen)
        buf_lo = addr - round_down(addr)
        buf_hi = buf_lo + length
        if buf_lo != 0:
            # Non-aligned write, read first machine word
            # (which will be partially overwritten with
            # passed `data`)
            word = self._jtag.memory_read(round_down(addr), 1)[0]
            i642bytes(word, buf, 0)
        if buf_hi != buflen:
            # Non-aligned write, read last machine word
            # (which will be partially overwritten with
            # passed `data`)
            word = self._jtag.memory_read(round_up(addr + length) - 8, 1)[0]
            i642bytes(word, buf, buflen - 8)
        buf[buf_lo:buf_hi] = data[0:length]
        for offset in range(0, buflen, 8):
            self._jtag.memory_write(round_down(addr) + offset, bytes2i64(buf, offset))

    def stop(self):
        self._jtag.stop()

    def step(self):
        self._jtag.step()

    def cont(self):
        self._jtag.start()

    def reset(self):
        self._jtag.stop()
        self._jtag.creset()
        # Perform the first step() which does (?) nothing
        self._jtag.step()

    def monitor(self, command_line: str, response: TextIO) -> bool:
        command, *args = command_line.split()
        if command == "status":
            assert len(args) == 0
            pass
        elif command == "step":
            assert len(args) == 0
            # Must flush register cache!
            self._cpustate.registers.flush()
            self._jtag.creset()
        elif command == "creset":
            assert len(args) == 0
            self._jtag.creset()
        elif command.startswith("gpr"):
            assert len(args) >= 1, "missing register name"
            assert args[0] in DBG_REGNAMES, "invalid register name"
            start = DBG_REGNAMES.index(args[0])
            if len(args) == 2:
                stop = min(start + int(args[1], base=0), len(DBG_REGNAMES))
            else:
                stop = start + 1
            for i in range(start, stop):
                v = self._jtag.register_read(i)
                response.write("%8s %016x\n" % (DBG_REGNAMES[i] + ":", v))
        elif command.startswith("mr"):
            assert len(args) >= 1, "missing address"
            addr = round_down(int(args[0], base=0))
            if len(args) == 2:
                count = int(args[1], base=0)
            else:
                count = 1
            for v in self._jtag.memory_read(addr, count):
                response.write("%016x: %016x\n" % (addr, v))
                addr += 8
        else:
            # Unsupported / invalid monitor command
            return False
        status = self._jtag.status_string()
        nia = self._jtag.register_read_nia()
        msr = self._jtag.register_read_msr()
        response.write("Core: %s\n NIA: %016x\n MSR: %016x\n" % (status, nia, msr))
        return True

    #
    # Software breakpoint support
    #
    SWBREAK_INSN = b"\x00\x00\x00\x48"

    def has_swbreak(self) -> bool:
        return True

    def hit_swbreak(self) -> bool:
        """
        Return true, if target hit one of the ss breakpoints
        """
        if self._jtag.status() == 0:  # is it running?
            nia = self._jtag.register_read_nia()
            if nia in self._sw_breakpoints:
                self._cpustate.registers.flush()
                self.stop()
                return True
        return False
