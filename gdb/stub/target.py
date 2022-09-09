class Target(object):
    @property
    def registers(self):
        return self._cpustate.registers

    def memory_read(self, address: int, length: int) -> bytes:
        raise Exception("Should be implemented!")


class Null(Target):
    def __init__(self, cpu_state):
        self._cpustate = cpu_state

    def memory_read(self, address: int, length: int) -> bytes:
        return bytes(length)
