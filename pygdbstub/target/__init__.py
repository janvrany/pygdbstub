import logging
from typing import TextIO

from ..arch import Arch


class Target(object):
    _logger = logging.getLogger(__name__)
    _cpustate: Arch

    #
    # Methods that must be implemented by individual targets
    #
    def connect(self):
        raise Exception("Should be implemented!")

    def disconnect(self):
        raise Exception("Should be implemented!")

    def memory_read(self, address: int, length: int) -> bytes:
        raise Exception("Should be implemented!")

    def register_read(self, regnum: int) -> bytes:
        raise Exception("Should be implemented!")

    def memory_write(self, address: int, data: bytes, length: int = None) -> None:
        raise Exception("Should be implemented!")

    def register_write(self, regnum: int, data: bytes) -> None:
        raise Exception("Should be implemented!")

    def stop(self):
        raise Exception("Should be implemented!")

    def step(self):
        raise Exception("Should be implemented!")

    def cont(self):
        raise Exception("Should be implemented!")

    def reset(self):
        raise Exception("Should be implemented!")

    # Additional methods that may be implemented (but are not
    # mandatory).

    def monitor(self, command: str, response: TextIO) -> bool | None:
        """
        Handle `monitor` command, writing response to passed
        `response` IO.
        Return:
            * `True` if command is supported (and response written)
            * `False` if command is not supported / malformed
            * `None` if target does not implement monitor commands

        """
        # By default, monitor commands are not supported.
        return None

    def has_swbreak(self) -> bool:
        """
        Return `True` if target support software breakpoints (implemented in
        stub), `False` otherwise.

        If `True` is returned, target MUST hasattr(target, 'SWBREAK_INSN') and
        it must be of type `bytes`.
        """
        return False

    def hit_swbreak(self) -> bool:
        """
        Return `True` is currently "stopped" at one of the software breakpoints,
        `False` otherwise.
        """
        assert self.has_swbreak(), "Called when has_swbreak() reports `False`!"
        raise Exception("Should be implemented!")

    # Common methods

    @property
    def registers(self):
        registers = self._cpustate.registers
        # Read registers if not already
        for reg in registers:
            if not reg.has_value:
                reg.set_bytes(self.register_read(reg.regnum))
        return registers

    def flush(self):
        """
        Flush all cached data, most notably registers.
        Called by Stub before resuming the target
        """
        self._cpustate.registers.flush()

    def set_swbreak(self, addr, kind):
        """
        Plant software breakpoint at given address.
        """
        assert self.has_swbreak(), "Called when has_swbreak() reports `False`!"
        assert hasattr(self, "SWBREAK_INSN"), "SWBREAK_INSN not defined!"
        assert self.SWBREAK_INSN is not None, "SWBREAK_INSN is None!"
        assert len(self.SWBREAK_INSN) == kind, "Requested swbreak length mistmatch"
        assert addr not in self._sw_breakpoints, "Breakpoint already installed!"

        self._sw_breakpoints[addr] = self.memory_read(addr, len(self.SWBREAK_INSN))
        self.memory_write(addr, self.SWBREAK_INSN)
        self._logger.debug(
            "planted sw breakpoint at 0x%016x (original code %s)"
            % (addr, self._sw_breakpoints[addr].hex())
        )

    def del_swbreak(self, addr, kind):
        """
        Remove previously planted software breakpoint.
        """
        assert self.has_swbreak(), "Called when has_swbreak() reports `False`!"
        assert addr in self._sw_breakpoints, "No swbreak at given address!"

        self.memory_write(addr, self._sw_breakpoints[addr])
        del self._sw_breakpoints[addr]
        self._logger.debug("removed sw breakpoint at 0x%016x" % addr)

    def del_swbreaks(self):
        """
        Remove ALL previously planted software breakpoint.
        """
        for addr, orig in self._sw_breakpoints:
            self.del_swbreak(addr, len(orig))

    def __init__(self):
        self._sw_breakpoints = {}

    #
    # __enter__ and __exit__ allow to use `with` statement.
    # This is useful for interactive work with target.
    #
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.del_swbreaks()
        self.disconnect()

    #
    # Ensure that gets disconnected when the object is gone.
    #
    def __del__(self):
        self.del_swbreaks()
        self.disconnect()


class Null(Target):
    def __init__(self, cpu_state: Arch):
        super().__init__()
        self._cpustate = cpu_state

    def connect(self):
        pass

    def disconnect(self):
        pass

    def memory_read(self, address: int, length: int) -> bytes:
        return bytes(length)

    def register_read(self, regnum: int) -> bytes:
        return self._cpustate.registers[regnum].get_bytes()

    def register_write(self, regnum, data):
        pass

    def memory_write(self, address: int, data: bytes, length: int = None) -> None:
        pass

    def stop(self):
        pass

    def step(self):
        pass

    def cont(self):
        pass

    def reset(self):
        pass
