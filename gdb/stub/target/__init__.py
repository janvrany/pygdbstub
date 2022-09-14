from gdb.stub.arch import Arch


class Target(object):
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

    @property
    def registers(self):
        registers = self._cpustate.registers
        # Read registers if not already
        for reg in registers:
            if not reg.has_value:
                reg.set_bytes(self.register_read(reg.regnum))
        return registers

    #
    # __enter__ and __exit__ allow to use `with` statement.
    # This is useful for interactive work with target.
    #
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    #
    # Ensure that gets disconnected when the object is gone.
    #
    def __del__(self):
        self.disconnect()


class Null(Target):
    def __init__(self, cpu_state: Arch):
        self._cpustate = cpu_state

    def connect(self):
        pass

    def disconnect(self):
        pass

    def memory_read(self, address: int, length: int) -> bytes:
        return bytes(length)

    def register_read(self, regnum: int) -> bytes:
        return self._cpustate.registers[regnum].get_bytes()
