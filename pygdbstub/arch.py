from struct import Struct


#
# Register types
#
class RegisterTypesLE:
    int32 = Struct("<i")
    int = int32

    uint32 = Struct("<I")
    uint64 = Struct("<Q")

    ieee_double = Struct("<d")

    def code_ptr(size):
        if size == 64:
            return RegisterTypesLE.uint64
        elif size == 32:
            return RegisterTypesLE.uint32
        else:
            raise Exception("Invalid pointer size")


class RegisterTypesBE:
    int32 = Struct(">i")
    int = int32

    uint32 = Struct(">I")
    uint64 = Struct(">Q")

    ieee_double = Struct(">d")

    def code_ptr(size):
        if size == 64:
            return RegisterTypesLE.uint64
        elif size == 32:
            return RegisterTypesLE.uint32
        else:
            raise Exception("Invalid pointer size")


class Register(object):
    def __init__(self, name, regnum, size, type, value=None):
        self._name = name
        self._regnum = regnum
        self._size = size
        self._type = type
        self._value = value

    @property
    def regnum(self):
        return self._regnum

    @property
    def name(self):
        return self._name

    @property
    def size(self):
        return self._size

    @property
    def has_value(self):
        return self._value is not None

    @property
    def value(self):
        return self.get()

    def __bytes__(self):
        return self.get_bytes()

    def __str__(self):
        if self._type == RegisterTypesLE.ieee_double:
            uintval = RegisterTypesLE.uint64.unpack(self.get_bytes())[0]
        elif self._type == RegisterTypesBE.ieee_double:
            uintval = RegisterTypesBE.uint64.unpack(self.get_bytes())[0]
        else:
            uintval = self.get()
        return f"[%02d] %-6s: 0x%0{self.size // 4}x (%s)" % (
            self._regnum,
            self._name,
            uintval,
            self.get(),
        )

    def get(self):
        if self._value is None:
            if self._type == RegisterTypesLE.ieee_double:
                return 0.0
            elif self._type == RegisterTypesBE.ieee_double:
                return 0.0
            else:
                return 0
        else:
            return self._value

    def set(self, value):
        if self._type == RegisterTypesLE.ieee_double:
            self._value = float(value)
        elif self._type == RegisterTypesBE.ieee_double:
            self._value = float(value)
        else:
            self._value = int(value)

    def get_bytes(self) -> bytes:
        return self._type.pack(self.get())

    def set_bytes(self, value: bytes) -> None:
        self.set(self._type.unpack(value)[0])

    def flush(self):
        self._value = None


class Registers(object):
    def __init__(self):
        self._registers = []

    def create(self, name, regnum, ignored, size, type):
        if regnum == len(self._registers):
            self._registers.append(Register(name, regnum, size, type))
        else:
            self._registers.append(Register(name, regnum, size, type))
            self._registers.sort(key=lambda r: r.regnum)

    def flush(self):
        for reg in self:
            reg.flush()

    def __getitem__(self, name_or_regnum):
        if isinstance(name_or_regnum, int):
            return self._registers[name_or_regnum]
        elif isinstance(name_or_regnum, str):
            for reg in self._registers:
                if reg.name == name_or_regnum:
                    return reg
            raise IndexError(f"No register named: #{name_or_regnum}")
        else:
            raise ValueError("Invalid parameter type")

    def __len__(self):
        return len(self._registers)

    def __iter__(self):
        return iter(self._registers)


class Arch(object):
    def __init__(self):
        self._registers = Registers()

    @property
    def registers(self):
        return self._registers


class PowerPC64(Arch):
    def __init__(self, little_endian=True):
        super().__init__()
        if little_endian:
            regtypes = RegisterTypesLE
        else:
            regtypes = RegisterTypesBE

        # Taken from gdb/features/rs6000/powerpc-64.c
        # GPRs
        self._registers.create("r0", 0, 1, 64, regtypes.uint64)
        self._registers.create("r1", 1, 1, 64, regtypes.uint64)
        self._registers.create("r2", 2, 1, 64, regtypes.uint64)
        self._registers.create("r3", 3, 1, 64, regtypes.uint64)
        self._registers.create("r4", 4, 1, 64, regtypes.uint64)
        self._registers.create("r5", 5, 1, 64, regtypes.uint64)
        self._registers.create("r6", 6, 1, 64, regtypes.uint64)
        self._registers.create("r7", 7, 1, 64, regtypes.uint64)
        self._registers.create("r8", 8, 1, 64, regtypes.uint64)
        self._registers.create("r9", 9, 1, 64, regtypes.uint64)
        self._registers.create("r10", 10, 1, 64, regtypes.uint64)
        self._registers.create("r11", 11, 1, 64, regtypes.uint64)
        self._registers.create("r12", 12, 1, 64, regtypes.uint64)
        self._registers.create("r13", 13, 1, 64, regtypes.uint64)
        self._registers.create("r14", 14, 1, 64, regtypes.uint64)
        self._registers.create("r15", 15, 1, 64, regtypes.uint64)
        self._registers.create("r16", 16, 1, 64, regtypes.uint64)
        self._registers.create("r17", 17, 1, 64, regtypes.uint64)
        self._registers.create("r18", 18, 1, 64, regtypes.uint64)
        self._registers.create("r19", 19, 1, 64, regtypes.uint64)
        self._registers.create("r20", 20, 1, 64, regtypes.uint64)
        self._registers.create("r21", 21, 1, 64, regtypes.uint64)
        self._registers.create("r22", 22, 1, 64, regtypes.uint64)
        self._registers.create("r23", 23, 1, 64, regtypes.uint64)
        self._registers.create("r24", 24, 1, 64, regtypes.uint64)
        self._registers.create("r25", 25, 1, 64, regtypes.uint64)
        self._registers.create("r26", 26, 1, 64, regtypes.uint64)
        self._registers.create("r27", 27, 1, 64, regtypes.uint64)
        self._registers.create("r28", 28, 1, 64, regtypes.uint64)
        self._registers.create("r29", 29, 1, 64, regtypes.uint64)
        self._registers.create("r30", 30, 1, 64, regtypes.uint64)
        self._registers.create("r31", 31, 1, 64, regtypes.uint64)
        self._registers.create("pc", 64, 1, 64, regtypes.code_ptr(64))
        self._registers.create("msr", 65, 1, 64, regtypes.uint64)
        self._registers.create("cr", 66, 1, 32, regtypes.uint32)
        self._registers.create("lr", 67, 1, 64, regtypes.code_ptr(64))
        self._registers.create("ctr", 68, 1, 64, regtypes.uint64)
        self._registers.create("xer", 69, 1, 32, regtypes.uint32)
        # FPRs
        self._registers.create("f0", 32, 1, 64, regtypes.ieee_double)
        self._registers.create("f1", 33, 1, 64, regtypes.ieee_double)
        self._registers.create("f2", 34, 1, 64, regtypes.ieee_double)
        self._registers.create("f3", 35, 1, 64, regtypes.ieee_double)
        self._registers.create("f4", 36, 1, 64, regtypes.ieee_double)
        self._registers.create("f5", 37, 1, 64, regtypes.ieee_double)
        self._registers.create("f6", 38, 1, 64, regtypes.ieee_double)
        self._registers.create("f7", 39, 1, 64, regtypes.ieee_double)
        self._registers.create("f8", 40, 1, 64, regtypes.ieee_double)
        self._registers.create("f9", 41, 1, 64, regtypes.ieee_double)
        self._registers.create("f10", 42, 1, 64, regtypes.ieee_double)
        self._registers.create("f11", 43, 1, 64, regtypes.ieee_double)
        self._registers.create("f12", 44, 1, 64, regtypes.ieee_double)
        self._registers.create("f13", 45, 1, 64, regtypes.ieee_double)
        self._registers.create("f14", 46, 1, 64, regtypes.ieee_double)
        self._registers.create("f15", 47, 1, 64, regtypes.ieee_double)
        self._registers.create("f16", 48, 1, 64, regtypes.ieee_double)
        self._registers.create("f17", 49, 1, 64, regtypes.ieee_double)
        self._registers.create("f18", 50, 1, 64, regtypes.ieee_double)
        self._registers.create("f19", 51, 1, 64, regtypes.ieee_double)
        self._registers.create("f20", 52, 1, 64, regtypes.ieee_double)
        self._registers.create("f21", 53, 1, 64, regtypes.ieee_double)
        self._registers.create("f22", 54, 1, 64, regtypes.ieee_double)
        self._registers.create("f23", 55, 1, 64, regtypes.ieee_double)
        self._registers.create("f24", 56, 1, 64, regtypes.ieee_double)
        self._registers.create("f25", 57, 1, 64, regtypes.ieee_double)
        self._registers.create("f26", 58, 1, 64, regtypes.ieee_double)
        self._registers.create("f27", 59, 1, 64, regtypes.ieee_double)
        self._registers.create("f28", 60, 1, 64, regtypes.ieee_double)
        self._registers.create("f29", 61, 1, 64, regtypes.ieee_double)
        self._registers.create("f30", 62, 1, 64, regtypes.ieee_double)
        self._registers.create("f31", 63, 1, 64, regtypes.ieee_double)
        self._registers.create("fpscr", 70, 1, 32, regtypes.int)
